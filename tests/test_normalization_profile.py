"""Synthetic compatibility regressions; no provider or private data access."""
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from communications.common import normalized, now
from communications.configuration import validate_config, validate_initial
from communications.store import Store, Denied
from communications.gateway import reconcile
from communications import admin, server

NUMBER = '+12025550123'
NATIONAL = '2025550123'

class NormalizationProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def store(self, profile='strict', name=None):
        store = Store(self.root / (name or profile) / 'messages.db', profile)
        store.owner('Synthetic owner', NUMBER)
        token = store.principal('fixture', ['messages:send', 'messages:read'], [NUMBER])
        return store, store.authenticate(token)

    def test_exact_legacy_shape_rules_and_strict_default(self):
        cases = [
            (NATIONAL, NUMBER, 'raw:' + NATIONAL),
            ('1' + NATIONAL, NUMBER, 'raw:1' + NATIONAL),
            ('(202) 555-0123', NUMBER, 'raw:(202) 555-0123'),
            (NUMBER, NUMBER, NUMBER),
            ('+12', 'raw:+12', '+12'),
            ('+1234567', 'raw:+1234567', '+1234567'),
            ('+12345678', '+12345678', '+12345678'),
            ('+123456789012345', '+123456789012345', '+123456789012345'),
            ('+1234567890123456', 'raw:+1234567890123456', 'raw:+1234567890123456'),
            ('12345', 'raw:12345', 'raw:12345'),
            ('1025550123', 'raw:1025550123', 'raw:1025550123'),
            ('2021550123', 'raw:2021550123', 'raw:2021550123'),
            ('  ALPHA  ', 'raw:ALPHA', 'raw:ALPHA'),
        ]
        for value, legacy, strict in cases:
            with self.subTest(value=value):
                self.assertEqual(normalized(value, 'legacy-nanp-v1'), legacy)
                self.assertEqual(normalized(value), strict)
                self.assertEqual(normalized(value, 'strict'), strict)
        for invalid in [None, '', 123, 'x' * 129]:
            for profile in ['strict', 'legacy-nanp-v1']:
                with self.assertRaises(ValueError): normalized(invalid, profile)

    def test_opt_in_validation_initial_setup_and_unknown_before_storage(self):
        self.assertEqual(validate_config({'data_dir': str(self.root)})['normalization_profile'], 'strict')
        self.assertEqual(validate_config({'data_dir': str(self.root), 'normalization_profile': 'legacy-nanp-v1'})['normalization_profile'], 'legacy-nanp-v1')
        initial = dict(gateway_url='http://127.0.0.1:8080', gateway_username='fixture', gateway_password='fixture', installed_version='fixture', owner_name='Fixture', owner_number=NUMBER, device_number='')
        self.assertEqual(validate_initial(initial, self.root)['normalization_profile'], 'strict')
        for bad in ['legacy', '', None, True, []]:
            with self.assertRaises(ValueError): validate_config({'data_dir': str(self.root), 'normalization_profile': bad})
            path = self.root / 'invalid' / 'messages.db'
            with self.assertRaises(ValueError): Store(path, bad)
            self.assertFalse(path.exists())

    def test_permission_intake_and_outbound_use_profile(self):
        for profile, permitted in [('strict', False), ('legacy-nanp-v1', True)]:
            store, principal = self.store(profile)
            with contextlib.closing(store.connect()) as db:
                self.assertEqual(store.policy(db, NATIONAL)['incoming_allowed'], permitted)
            if permitted: store.require(principal, 'messages:send', NATIONAL)
            else:
                with self.assertRaises(Denied): store.require(principal, 'messages:send', NATIONAL)
            event = {'payload': {'sender': NATIONAL, 'recipient': NUMBER, 'receivedAt': now(), 'message': 'Synthetic intake'}, 'fullBodyVerified': True}
            store.intake('fixture-device', 'fixture-inbound', 'poll', 'sms:received', event)
            store.process_events()
            with contextlib.closing(store.connect()) as db:
                row = db.execute('SELECT * FROM messages').fetchone()
                self.assertEqual(row['route_state'], 'permitted' if permitted else 'unauthorized')
                self.assertEqual(row['sender_raw'], NATIONAL)
            if permitted:
                mid = store.enqueue(principal, NATIONAL, 'Synthetic outbound', 'fixture-key-0001')
                self.assertEqual(mid, store.enqueue(principal, NUMBER, 'Synthetic outbound', 'fixture-key-0001'))
            else:
                with self.assertRaises(Denied): store.enqueue(principal, NATIONAL, 'Synthetic outbound', 'fixture-key-0001')

    def test_association_principal_and_block_profile_boundaries(self):
        for profile, expected in [('strict', 'raw:' + NATIONAL), ('legacy-nanp-v1', NUMBER)]:
            store = Store(self.root / profile / 'messages.db', profile)
            contact = store.contact('Fixture')
            self.assertEqual(store.identifier(contact, NATIONAL), expected)
            principal = store.authenticate(store.principal('fixture', ['messages:send'], [NATIONAL]))
            self.assertEqual(principal['numbers'], [expected])
            store.block(NATIONAL, True)
            with contextlib.closing(store.connect()) as db:
                self.assertEqual(store.policy(db, NUMBER)['blocked'], profile == 'legacy-nanp-v1')

    def test_status_and_receipts_use_profile(self):
        for profile, compatible in [('strict', False), ('legacy-nanp-v1', True)]:
            store, principal = self.store(profile)
            mid = store.enqueue(principal, NUMBER, 'Synthetic status', 'fixture-key-0001')
            with contextlib.closing(store.connect()) as db: message = dict(db.execute('SELECT * FROM messages WHERE id=?', (mid,)).fetchone())
            gateway = MagicMock()
            gateway.status.return_value = {'id': message['provider_id'], 'state': 'Sent', 'recipients': [{'phoneNumber': NATIONAL}], 'textMessage': {'text': message['body']}}
            reconcile(store, gateway, message)
            with contextlib.closing(store.connect()) as db:
                row = db.execute('SELECT state,last_error FROM messages WHERE id=?', (mid,)).fetchone()
                self.assertEqual(row['last_error'], None if compatible else 'status_recipient_mismatch')
            store.intake('fixture-device', 'fixture-receipt', 'webhook', 'sms:sent', {'payload': {'messageId': message['provider_id'], 'recipient': NATIONAL, 'partsCount': 1}})
            store.process_events()
            with contextlib.closing(store.connect()) as db:
                self.assertEqual(db.execute('SELECT state FROM events').fetchone()[0], 'processed' if compatible else 'quarantined')
            gateway.send.assert_not_called()

    def test_profiles_are_instance_scoped_and_do_not_rewrite_history(self):
        legacy, _ = self.store('legacy-nanp-v1')
        with contextlib.closing(legacy.connect()) as db: before = list(db.iterdump())
        strict = Store(legacy.path)
        with contextlib.closing(strict.connect()) as db: self.assertEqual(list(db.iterdump()), before)
        self.assertEqual(legacy.normalize(NATIONAL), NUMBER)
        self.assertEqual(strict.normalize(NATIONAL), 'raw:' + NATIONAL)
        self.assertEqual(normalized(NATIONAL), 'raw:' + NATIONAL)

    def test_server_and_admin_select_configured_profile(self):
        root = self.root / 'configured'; root.mkdir(mode=0o700)
        config = self.root / 'config.json'
        config.write_text(json.dumps({'data_dir': str(root), 'normalization_profile': 'legacy-nanp-v1', 'outbound_enabled': False}))
        config.chmod(0o600)
        with patch('sys.argv', ['admin', '--config', str(config), 'health']), patch.object(admin, 'Store', wraps=Store) as factory, contextlib.redirect_stdout(io.StringIO()):
            admin.main()
            factory.assert_called_once_with(root / 'messages.db', 'legacy-nanp-v1')
        class EndBeforeListening(Exception): pass
        with open(root / 'service.lock', 'a') as lock, patch.object(server, 'open', return_value=lock, create=True), patch('sys.argv', ['server', '--config', str(config)]), patch.object(server, 'Store', wraps=Store) as factory, patch.object(server, 'Server', side_effect=EndBeforeListening):
            with self.assertRaises(EndBeforeListening): server.main()
            factory.assert_called_once_with(root / 'messages.db', 'legacy-nanp-v1')

if __name__ == '__main__': unittest.main()
