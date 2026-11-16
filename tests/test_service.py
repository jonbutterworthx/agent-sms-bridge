import contextlib
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from communications.common import normalized, now
from communications.gateway import Gateway, GatewayError, dispatch_one, reconcile, recover_interrupted
from communications.server import Server
from communications.store import Conflict, Denied, Store

OWNER = '+12025550123'
UNKNOWN = '+12025550124'
SECOND = '+12025550125'
DEVICE = '+12025550126'
DATE = '2026-11-13T14:30:00.000+00:00'


def incoming(ident='event-1', body='Hello', sender=OWNER, at=DATE, provider='collision-id'):
    return {'id': ident, 'deviceId': 'test-device', 'webhookId': 'incoming-hook', 'event': 'sms:received',
            'payload': {'messageId': provider, 'message': body, 'sender': sender,
                        'recipient': DEVICE, 'simNumber': 1, 'receivedAt': at}}


class FakeGateway:
    def __init__(self, failure=False):
        self.sent = []
        self.failure = failure
        self.result = None

    def send(self, message):
        self.sent.append(dict(message))
        if self.failure:
            raise GatewayError('transport_or_invalid_response')
        return {'id': message['provider_id'], 'state': 'Pending'}

    def status(self, ident):
        if self.result is None:
            raise GatewayError('http_404')
        return self.result


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'messages.db')
        self.store.meta('started_at', '2026-11-13T00:00:00.000+00:00')
        self.owner = self.store.owner('Owner', OWNER)
        self.token = self.store.principal('test-client', ['messages:read','messages:send','contacts:read',
            'permissions:read','status:read','health:read'], [OWNER, UNKNOWN, SECOND])
        self.principal = self.store.authenticate(self.token)

    def tearDown(self):
        self.tmp.cleanup()

    def rows(self, table='messages'):
        with contextlib.closing(self.store.connect()) as db:
            return [dict(row) for row in db.execute('SELECT * FROM ' + table)]

    def event(self, event, source='webhook'):
        self.store.intake('test-device', event['id'], source, event['event'], event)

    def outgoing(self, key='request-0001', recipient=OWNER):
        return self.store.enqueue(self.principal, recipient, 'Test outbound', key)


class IntakeTests(Base):
    def test_full_unicode_multipart_is_stored_before_routing(self):
        text = ('Test ☀️ / 漢字 / \n' * 250) + 'END-CHECK'
        self.event(incoming(body=text))
        self.assertEqual(len(self.rows('events')), 1)
        self.assertEqual(self.rows(), [])
        self.store = Store(self.root / 'messages.db')
        self.store.process_events()
        row = self.rows()[0]
        self.assertEqual(row['body'], text)
        self.assertEqual(row['route_state'], 'permitted')
        self.assertEqual(row['content_state'], 'complete_verified')

    def test_duplicate_envelope_and_poll_are_idempotent(self):
        event = incoming()
        for _ in range(3):
            self.event(event)
        self.store.process_events()
        poll = incoming('poll-1')
        poll['fullBodyVerified'] = True
        self.event(poll, 'poll')
        self.store.process_events()
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(len(self.rows('events')), 2)

    def test_identical_body_new_timestamp_and_provider_id_collision_preserved(self):
        self.event(incoming())
        self.event(incoming('event-2', at='2026-11-13T14:30:01.000+00:00'))
        self.event(incoming('event-3', body='Different', at='2026-11-13T14:30:00.000+00:00'))
        self.store.process_events()
        self.assertEqual(len(self.rows()), 3)
        self.assertEqual(len({m['provider_id'] for m in self.rows()}), 1)

    def test_indistinguishable_distinct_webhook_occurrences_retained_ambiguous(self):
        self.event(incoming())
        self.event(incoming('event-2'))
        self.store.process_events()
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(self.rows()[1]['route_state'], 'ambiguous_identity')

    def test_conflicting_transport_identity_quarantines_without_overwrite(self):
        self.event(incoming())
        self.event(incoming(body='conflicting text'))
        self.store.process_events()
        self.assertEqual(len(self.rows('events')), 2)
        self.assertEqual(self.rows('events')[1]['state'], 'quarantined')
        self.assertEqual(self.rows()[0]['body'], 'Hello')

    def test_unknown_retained_no_contact_no_reply(self):
        self.event(incoming(sender=UNKNOWN))
        self.store.process_events()
        row = self.rows()[0]
        self.assertEqual(row['route_state'], 'unauthorized')
        self.assertIsNone(row['contact_id'])
        self.assertEqual(len(self.rows('contacts')), 1)
        self.assertEqual(self.rows('attempts'), [])
        self.assertEqual(self.store.history(self.principal), [])

    def test_history_association_does_not_grant_permission_or_replay(self):
        self.event(incoming(sender=UNKNOWN))
        self.store.process_events()
        contact = self.store.contact('Known but unauthorized')
        self.store.identifier(contact, UNKNOWN)
        row = self.rows()[0]
        self.assertEqual(row['contact_id'], contact)
        self.assertEqual(row['route_state'], 'unauthorized')
        self.assertEqual(self.store.history(self.principal), [])

    def test_block_overrides_owner_but_not_other_number(self):
        self.store.identifier(self.owner, SECOND)
        self.store.block(OWNER, True, 'manual test')
        self.event(incoming())
        self.store.process_events()
        self.assertEqual(self.rows()[0]['route_state'], 'blocked')
        with contextlib.closing(self.store.connect()) as db:
            self.assertTrue(self.store.policy(db, OWNER)['blocked'])
            self.assertFalse(self.store.policy(db, SECOND)['blocked'])
            self.assertFalse(self.store.policy(db, SECOND)['outgoing_allowed'])
        self.store.block(OWNER, False)
        with contextlib.closing(self.store.connect()) as db:
            self.assertTrue(self.store.policy(db, OWNER)['outgoing_allowed'])

    def test_preblocked_owner_stays_blocked(self):
        other = Store(self.root / 'other.db')
        other.block(OWNER, True)
        other.owner('Owner', OWNER)
        with contextlib.closing(other.connect()) as db:
            self.assertFalse(other.policy(db, OWNER)['outgoing_allowed'])

    def test_historical_backfill_never_new_work(self):
        self.event(incoming(at='2026-11-12T23:59:59Z'))
        self.store.process_events()
        self.assertEqual(self.rows()[0]['route_state'], 'historical')
        self.assertEqual(self.rows()[0]['historical'], 1)
        self.assertEqual(self.rows()[0]['historical'], 1)

    def test_unverified_preview_not_exposed_as_full_body(self):
        self.event(incoming(), 'poll')
        self.store.process_events()
        self.assertEqual(self.rows()[0]['content_state'], 'preview_unverified')
        self.assertEqual(self.store.history(self.principal), [])

    def test_normalization_and_original_are_separate(self):
        self.event(incoming(sender='(202) 555-0123'))
        self.store.process_events()
        row = self.rows()[0]
        self.assertEqual(row['sender_raw'], '(202) 555-0123')
        self.assertEqual(row['peer'], 'raw:(202) 555-0123')
        self.assertIsNone(row['contact_id'])
        self.assertEqual(normalized('12345'), 'raw:12345')
        self.assertEqual(normalized('+44 (7700) 900123'), '+447700900123')


class OutboundTests(Base):
    def test_idempotency_survives_restart(self):
        ident = self.outgoing()
        gateway = FakeGateway()
        dispatch_one(self.store, gateway)
        self.store = Store(self.root / 'messages.db')
        self.assertEqual(ident, self.outgoing())
        dispatch_one(self.store, gateway)
        self.assertEqual(len(gateway.sent), 1)
        with self.assertRaises(Conflict):
            self.store.enqueue(self.principal, OWNER, 'different', 'request-0001')

    def test_unknown_known_unauthorized_and_blocked_cannot_send(self):
        self.outgoing(recipient=UNKNOWN)
        known = self.store.contact('Known')
        self.store.identifier(known, SECOND)
        self.outgoing(key='request-0002', recipient=SECOND)
        self.store.block(OWNER, True)
        self.outgoing(key='request-0003')
        gateway = FakeGateway()
        dispatch_one(self.store, gateway)
        self.assertEqual(gateway.sent, [])
        self.assertTrue(all(row['state'] == 'denied' for row in self.rows()))

    def test_block_and_revoke_after_queue_before_dispatch(self):
        self.outgoing()
        self.store.block(OWNER, True)
        gateway = FakeGateway()
        dispatch_one(self.store, gateway)
        self.assertEqual(gateway.sent, [])
        self.store.block(OWNER, False)
        self.outgoing('request-0002')
        with self.store.transaction() as db:
            db.execute('UPDATE principals SET active=0')
        dispatch_one(self.store, gateway)
        self.assertEqual(gateway.sent, [])

    def test_ambiguous_timeout_and_404_never_resends(self):
        self.outgoing()
        gateway = FakeGateway(failure=True)
        dispatch_one(self.store, gateway)
        self.assertEqual(self.rows()[0]['state'], 'unknown')
        recover_interrupted(self.store)
        reconcile(self.store, gateway, self.rows()[0])
        dispatch_one(self.store, gateway)
        self.assertEqual(len(gateway.sent), 1)
        self.assertEqual(self.rows()[0]['state'], 'unknown')
        self.assertEqual(self.rows()[0]['last_error'], 'http_404')

    def test_crash_between_commit_and_send_becomes_unknown(self):
        ident = self.outgoing()
        with self.store.transaction() as db:
            db.execute("UPDATE messages SET state='submitting'")
            db.execute("INSERT INTO attempts(message_id,started_at,result) VALUES(?,?,'started')", (ident, now()))
        recover_interrupted(Store(self.root / 'messages.db'))
        gateway = FakeGateway()
        dispatch_one(self.store, gateway)
        self.assertEqual(gateway.sent, [])
        self.assertEqual(self.rows()[0]['state'], 'unknown')
        self.assertEqual(self.rows('attempts')[0]['result'], 'unknown')

    def test_rate_limit_survives_restart(self):
        for i in range(7):
            self.outgoing('request-%04d' % i)
        gateway = FakeGateway()
        for _ in range(7):
            dispatch_one(self.store, gateway)
        self.store = Store(self.root / 'messages.db')
        dispatch_one(self.store, gateway)
        self.assertEqual(len(gateway.sent), 5)
        self.assertEqual(sum(r['state'] == 'queued' for r in self.rows()), 2)

    def test_scope_denies_arbitrary_recipient(self):
        token = self.store.principal('restricted', ['messages:send'], [OWNER])
        principal = self.store.authenticate(token)
        with self.assertRaises(Denied):
            self.store.enqueue(principal, UNKNOWN, 'message', 'request-0000')
        with self.assertRaises(Denied):
            self.store.history(principal)

    def test_aggregate_delivered_is_not_all_parts(self):
        self.outgoing()
        gateway = FakeGateway()
        dispatch_one(self.store, gateway)
        message = self.rows()[0]
        gateway.result = {'id': message['provider_id'], 'state': 'Delivered',
                         'recipients': [{'phoneNumber': OWNER, 'state': 'Delivered'}]}
        reconcile(self.store, gateway, message)
        self.assertEqual(self.rows()[0]['delivery_state'], 'partial_or_unquantified')

    def test_all_parts_require_distinct_delivery_envelopes_and_sent_count(self):
        self.outgoing()
        gateway = FakeGateway()
        dispatch_one(self.store, gateway)
        message = self.rows()[0]
        sent = {'id': 'sent', 'event': 'sms:sent', 'payload': {'messageId': message['provider_id'], 'recipient': OWNER, 'partsCount': 2}}
        delivered = {'id': 'delivered-1', 'event': 'sms:delivered', 'payload': {'messageId': message['provider_id'], 'recipient': OWNER}}
        self.event(delivered)
        self.event(delivered)
        self.event(sent)
        self.store.process_events()
        self.assertEqual(self.rows()[0]['receipts'], 1)
        self.assertEqual(self.rows()[0]['delivery_state'], 'partial_or_unquantified')
        delivered['id'] = 'delivered-2'
        self.event(delivered)
        self.store.process_events()
        self.assertEqual(self.rows()[0]['delivery_state'], 'confirmed_all_parts')

    def test_wrong_status_identity_does_not_confirm(self):
        self.outgoing()
        gateway = FakeGateway()
        dispatch_one(self.store, gateway)
        message = self.rows()[0]
        gateway.result = {'id': 'wrong', 'state': 'Delivered'}
        reconcile(self.store, gateway, message)
        self.assertEqual(self.rows()[0]['delivery_state'], 'unconfirmed')
        self.assertEqual(self.rows()[0]['last_error'], 'status_identity_mismatch')


class PollTests(Base):
    def test_poll_dates_match_installed_smsgate_parser(self):
        import urllib.parse
        self.store.meta('poll_cursor', '2026-11-13T14:30:00.123+00:00')
        gateway = self.gateway([([], {'X-Total-Count': '0'})])
        gateway.poll(self.store)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(gateway.calls[0][1]).query)
        self.assertEqual(query['from'], ['2026-11-12T14:30:00.123+00:00'])
        for name in ('from', 'to'):
            self.assertRegex(query[name][0], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+]00:00$')

    def gateway(self, pages, verified=True):
        gateway = object.__new__(Gateway)
        gateway.config = {'device_id': 'test-device', 'inbox_full_body_verified': verified,
                          'inbox_verification_evidence': 'synthetic-test'}
        calls = []
        def request(method, path):
            calls.append((method, path))
            result = pages[len(calls)-1]
            if isinstance(result, Exception):
                raise result
            return result
        gateway.request = request
        gateway.calls = calls
        return gateway

    def row(self, ident='id', text='Full text', date=DATE):
        return {'id': ident, 'type': 'SMS', 'sender': OWNER, 'recipient': DEVICE,
                'simNumber': 1, 'createdAt': date, 'contentPreview': text}

    def test_repeated_polls_distinct_messages_and_initial_history(self):
        rows = [self.row(), self.row(date='2026-11-13T14:30:01.000+00:00')]
        for _ in range(3):
            gateway = self.gateway([(rows, {'X-Total-Count': '2'})])
            gateway.poll(self.store)
            self.store.process_events()
        self.assertEqual(len(self.rows()), 2)
        self.assertTrue(all(row['historical'] for row in self.rows()))
        self.assertEqual(len(self.rows('events')), 2)
        self.assertTrue(all(row['state'] == 'processed' for row in self.rows('events')))

    def test_partial_scan_does_not_advance_cursor_but_commits_received_pages(self):
        self.store.meta('poll_cursor', DATE)
        gateway = self.gateway([([self.row()], {'X-Total-Count': '2'}), GatewayError('offline')])
        with self.assertRaises(GatewayError):
            gateway.poll(self.store)
        self.assertEqual(self.store.meta('poll_cursor'), DATE)
        self.assertEqual(len(self.rows('events')), 1)

    def test_changing_total_stops_scan(self):
        gateway = self.gateway([([self.row()], {'X-Total-Count': '2'}), ([self.row('id2')], {'X-Total-Count': '3'})])
        with self.assertRaises(GatewayError):
            gateway.poll(self.store)
        self.assertIsNone(self.store.meta('poll_cursor'))

    def test_verification_upgrade_preserves_one_record_and_historical_routing(self):
        for verified in (False, True):
            self.gateway([([self.row()], {'X-Total-Count': '1'})], verified).poll(self.store)
            self.store.process_events()
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]['content_state'], 'complete_verified')
        self.assertEqual(self.rows()[0]['route_state'], 'historical')


class RecoveryTests(Base):
    def test_online_backup_and_isolated_restore_all_tables(self):
        self.event(incoming(body='Sensitive synthetic full body'))
        self.store.process_events()
        self.outgoing()
        self.store.block(UNKNOWN, True)
        backup = self.store.backup(self.root / 'backup.db')
        restored_path = self.root / 'restored.db'
        with contextlib.closing(sqlite3.connect(backup)) as source, contextlib.closing(sqlite3.connect(restored_path)) as restored:
            source.backup(restored)
            self.assertEqual(restored.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(list(source.iterdump()), list(restored.iterdump()))
        restored = Store(restored_path)
        with contextlib.closing(self.store.connect()) as live, contextlib.closing(restored.connect()) as recovered:
            for table in ('messages','events','contacts','identifiers','number_policy','principals','attempts','metadata'):
                self.assertEqual([tuple(r) for r in live.execute('SELECT * FROM '+table)],
                                 [tuple(r) for r in recovered.execute('SELECT * FROM '+table)])
        self.assertEqual(os.stat(backup).st_mode & 0o777, 0o600)
        with contextlib.closing(self.store.connect()) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0], 2)

    def test_real_process_restart_recovery_and_admin_restore(self):
        self.event(incoming())
        ident = self.outgoing()
        with self.store.transaction() as db:
            db.execute("UPDATE messages SET state='submitting' WHERE id=?", (ident,))
            db.execute("INSERT INTO attempts(message_id,started_at,result) VALUES(?,?,'started')", (ident, now()))
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            port = available.getsockname()[1]
        config = self.root / 'config.json'
        config.write_text(json.dumps({'data_dir': str(self.root), 'api_port': port, 'outbound_enabled': False}))
        config.chmod(0o600)
        captures = []
        for _ in range(2):
            process = subprocess.Popen([sys.executable, '-B', '-m', 'communications.server', '--config', str(config)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ready = False
                for retry in range(50):
                    try:
                        req = urllib.request.Request('http://127.0.0.1:%d/v1/health' % port,
                                                     headers={'Authorization': 'Bearer '+self.token})
                        with urllib.request.urlopen(req, timeout=1) as response:
                            data = json.load(response)
                            ready = data['events_pending'] == 0
                        if ready:
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(.1)
                self.assertTrue(ready)
            finally:
                process.terminate()
                out, err = process.communicate(timeout=10)
                captures.append(out + err)
            self.assertEqual(process.returncode, 0)
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(next(r['state'] for r in self.rows() if r['id'] == ident), 'unknown')
        self.assertEqual(len(self.rows('attempts')), 1)
        backup = self.store.backup(self.root / 'process-backup.db')
        restored = self.root / 'isolated-restore'
        run = subprocess.run([sys.executable,'-B','-m','communications.admin','--config',str(config),
            'verify-restore','--backup',str(backup),'--destination',str(restored)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(run.stdout)['logical_content_equal'])
        for output in captures:
            self.assertNotIn(OWNER.encode(), output)
            self.assertNotIn(b'Test outbound', output)
            self.assertNotIn(self.token.encode(), output)


class HTTPTests(Base):
    def setUp(self):
        super().setUp()
        self.config = {'device_id': 'test-device', 'webhook_signing_key': 'synthetic-signing-key',
                       'webhook_ids': ['incoming-hook'], 'webhook_source_ips': ['127.0.0.1']}
        self.server = Server(('127.0.0.1', 0), self.store, self.config)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        super().tearDown()

    def request(self, path, body=None, headers=None):
        hdr = {'Authorization': 'Bearer ' + self.token}
        if headers:
            hdr.update(headers)
        if body is not None:
            hdr['Content-Type'] = 'application/json'
            body = json.dumps(body).encode() if not isinstance(body, bytes) else body
        request = urllib.request.Request(self.url + path, data=body, headers=hdr)
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.load(response), response.headers

    def test_auth_validation_no_browser_origin_and_no_admin_api(self):
        self.assertEqual(self.request('/v1/health', headers={'Authorization': 'Bearer bad'})[0], 401)
        self.assertEqual(self.request('/v1/health', headers={'Origin': 'http://evil.test'})[0], 403)
        self.assertEqual(self.request('/v1/admin')[0], 404)
        self.assertEqual(self.request('/v1/messages', b'{"recipient":"x","recipient":"y"}')[0], 400)
        self.assertEqual(self.request('/v1/messages', {'recipient': OWNER, 'body': 'x', 'idempotency_key':'request-1', 'extra': True})[0], 400)
        status, data, headers = self.request('/v1/health')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertNotIn(OWNER, json.dumps(data))

    def test_outbound_status_end_to_end(self):
        status, data, _ = self.request('/v1/messages', {'recipient': OWNER,'body':'test','idempotency_key':'request-0001'})
        self.assertEqual(status, 202)
        gateway = FakeGateway()
        dispatch_one(self.store, gateway)
        status, data, _ = self.request('/v1/messages/'+data['id'])
        self.assertEqual(data['state'], 'submitted')
        self.assertEqual(data['attempts'], 1)

    def test_signed_webhook_durable_ack_replay_and_rejection(self):
        self.server.webhook_only = True
        event = incoming(body='Full body from signed event')
        raw = json.dumps(event).encode()
        stamp = str(int(time.time()))
        signature = hmac.new(self.config['webhook_signing_key'].encode(), raw+stamp.encode(), hashlib.sha256).hexdigest()
        headers = {'X-Timestamp': stamp, 'X-Signature': signature}
        self.assertEqual(self.request('/webhooks/smsgate', raw, headers)[0], 202)
        self.assertEqual(self.request('/webhooks/smsgate', raw, headers)[0], 202)
        self.assertEqual(len(self.rows('events')), 1)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.request('/webhooks/smsgate', raw, {'X-Timestamp':stamp,'X-Signature':'wrong'})[0], 403)
        self.assertEqual(self.request('/webhooks/smsgate', raw, {'X-Timestamp':'1','X-Signature':signature})[0], 403)
        self.assertEqual(self.request('/v1/messages')[0], 404)


if __name__ == '__main__':
    unittest.main()
