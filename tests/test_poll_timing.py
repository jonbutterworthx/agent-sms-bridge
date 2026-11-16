import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from communications.common import load_config, poll_interval
from communications.server import worker
from communications.configuration import validate_config


class PollTimingTests(unittest.TestCase):
    def test_config_validation_and_compatibility(self):
        self.assertEqual(poll_interval({}), 60)
        for value in (10, 60, 3600):
            self.assertEqual(poll_interval({'poll_seconds': value}), value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            for value in (True, False, None, '10', 10.5, 0, 9, 3601):
                path.write_text(json.dumps({'poll_seconds': value, 'data_dir': directory}))
                path.chmod(0o600)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    load_config(path)

    def test_slow_polls_wait_configured_interval_after_completion(self):
        clock = [0]
        starts = []
        running = [False]
        store = Mock()
        store.connect.return_value.execute.return_value.fetchall.return_value = []
        stop = Mock()
        stop.is_set.side_effect = lambda: len(starts) >= 3
        stop.wait.side_effect = lambda seconds: clock.__setitem__(0, clock[0] + seconds)
        def poll(_):
            self.assertFalse(running[0])
            running[0] = True
            starts.append(clock[0])
            clock[0] += 5  # A slow request must never overlap or catch up in a burst.
            running[0] = False
        with patch('communications.server.Gateway') as gateway, patch('communications.server.time.monotonic', side_effect=lambda: clock[0]):
            gateway.return_value.poll.side_effect = poll
            worker(store, {'gateway_url': 'http://127.0.0.1:8080', 'poll_seconds': 10}, stop)
        self.assertEqual(starts, [0, 15, 30])
        self.assertEqual(store.meta.call_count, 3)

    def test_interval_bounds_preserve_generalized_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            for value in (10, 11, 60, 3600):
                self.assertEqual(validate_config({'data_dir': directory, 'poll_seconds': value})['poll_seconds'], value)
            self.assertEqual(validate_config({'data_dir': directory})['poll_seconds'], 60)
            for extra in ({'api_port': True}, {'webhook_enabled': True}, {'outbound_enabled': 'yes'},
                          {'gateway_url': 'http://8.8.8.8:8080'}, {'owner_number': '2025550123'},
                          {'inbox_full_body_verified': True}, {'data_dir': '/'}):
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    validate_config({'data_dir': directory, 'poll_seconds': 10, **extra})

    def test_failed_poll_respects_interval_without_busy_retry(self):
        from communications.gateway import GatewayError
        clock = [0]
        starts = []
        store = Mock()
        store.connect.return_value.execute.return_value.fetchall.return_value = []
        stop = Mock()
        stop.is_set.side_effect = lambda: len(starts) >= 3
        stop.wait.side_effect = lambda seconds: clock.__setitem__(0, clock[0] + seconds)
        def poll(_):
            starts.append(clock[0])
            clock[0] += 5
            raise GatewayError('transport_or_invalid_response')
        with patch('communications.server.Gateway') as gateway, patch('communications.server.time.monotonic', side_effect=lambda: clock[0]):
            gateway.return_value.poll.side_effect = poll
            worker(store, {'gateway_url': 'http://127.0.0.1:8080', 'poll_seconds': 10}, stop)
        self.assertEqual(starts, [0, 15, 30])
        store.meta.assert_called_with('last_poll_error', 'transport_or_invalid_response')
