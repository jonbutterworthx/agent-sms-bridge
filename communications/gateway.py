"""SMSGate Local Server only. No retries of POST /message, redirects or proxy use."""
import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from .common import digest, now, timestamp


class GatewayError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Gateway:
    def __init__(self, config):
        self.config = config
        self.base = config['gateway_url'].rstrip('/')
        context = ssl.create_default_context(cafile=config.get('gateway_ca_file'))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                 urllib.request.HTTPSHandler(context=context))

    def request(self, method, path, body=None):
        credentials = (self.config['gateway_username'] + ':' + self.config['gateway_password']).encode()
        request = urllib.request.Request(self.base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Basic ' + base64.b64encode(credentials).decode(),
                     'Content-Type': 'application/json', 'Accept': 'application/json'})
        try:
            with self.opener.open(request, timeout=15) as response:
                payload = response.read(16 * 1024 * 1024 + 1)
                if len(payload) > 16 * 1024 * 1024:
                    raise GatewayError('response_too_large')
                return json.loads(payload) if payload else {}, dict(response.headers)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise GatewayError('http_' + str(exc.code)) from None
        except (OSError, ValueError, urllib.error.URLError):
            raise GatewayError('transport_or_invalid_response') from None

    def send(self, message):
        return self.request('POST', '/message', {'id': message['provider_id'],
            'textMessage': {'text': message['body']}, 'phoneNumbers': [message['peer']],
            'withDeliveryReport': True, 'ttl': 300})[0]

    def status(self, provider_id):
        return self.request('GET', '/message/' + urllib.parse.quote(provider_id, safe=''))[0]

    def poll(self, store):
        config = self.config
        # A version string alone is not body verification. Require an evidence reference
        # and a successful long/multipart comparison before treating this field as full.
        verified = bool(config.get('inbox_full_body_verified') and config.get('inbox_verification_evidence'))
        cursor = store.meta('poll_cursor')
        end = now()
        cutover = store.meta('poll_initial_cutover')
        if cutover is None:
            cutover = store.meta('poll_initial_cutover', end)
        # SMSGate 1.78.3's DateTimeParser accepts exactly 0 or 3 fractional digits.
        start = (datetime.fromisoformat(cursor) - timedelta(days=1)).isoformat(timespec='milliseconds') if cursor else '1970-01-01T00:00:00+00:00'
        offset, expected = 0, None
        while True:
            query = urllib.parse.urlencode({'type': 'SMS', 'from': start, 'to': end, 'limit': 100, 'offset': offset})
            rows, headers = self.request('GET', '/inbox?' + query)
            total = int(next((v for k, v in headers.items() if k.lower() == 'x-total-count'), '-1'))
            if not isinstance(rows, list) or total < 0 or len(rows) > 100:
                raise GatewayError('invalid_inbox_contract')
            if expected is not None and total != expected:
                raise GatewayError('inbox_changed_during_page_scan')
            expected = total
            for row in rows:
                if row.get('type') != 'SMS':
                    raise GatewayError('unexpected_message_type')
                # No reliance on provider's content-based ID as a unique message identity.
                transport = digest([row.get(k) for k in ('id', 'type', 'sender', 'recipient', 'simNumber', 'createdAt', 'contentPreview')] + [verified])
                event = {'payload': {'messageId': row['id'], 'sender': row['sender'],
                    'recipient': row.get('recipient'), 'simNumber': row.get('simNumber'),
                    'receivedAt': row['createdAt'], 'message': row['contentPreview']},
                    'fullBodyVerified': verified, 'historical': timestamp(row['createdAt']) <= cutover}
                store.intake(config.get('device_id', 'local-sms-device'), transport, 'poll', 'sms:received', event)
            offset += len(rows)
            if offset >= total:
                break
            if not rows or offset > 100000:
                raise GatewayError('incomplete_inbox_pagination')
        store.meta('poll_cursor', end)
        store.meta('last_poll_ok', now())


def reconcile(store, gateway, message):
    try:
        result = gateway.status(message['provider_id'])
        if not isinstance(result, dict):
            raise GatewayError('invalid_status_contract')
        if result.get('id') != message['provider_id']:
            raise GatewayError('status_identity_mismatch')
        recipients = result.get('recipients', [])
        from .common import normalized
        if not recipients or any(normalized(r['phoneNumber']) != message['peer'] for r in recipients):
            raise GatewayError('status_recipient_mismatch')
        text = result.get('textMessage', {}).get('text')
        if text is not None and text != message['body']:
            raise GatewayError('status_content_mismatch')
        state = result.get('state')
        states = {'Pending': 'submitted', 'Processed': 'processed_unconfirmed', 'Sent': 'sent',
                  'Delivered': 'sent', 'Failed': 'failed', 'Cancelled': 'cancelled'}
        if state not in states:
            raise GatewayError('unknown_provider_state')
        with store.transaction() as db:
            serialized = json.dumps(result, sort_keys=True)
            prior = db.execute("SELECT raw FROM status_observations WHERE message_id=? AND source='status_poll' ORDER BY id DESC LIMIT 1", (message['id'],)).fetchone()
            if not prior or prior[0] != serialized:
                db.execute('INSERT INTO status_observations(message_id,observed_at,source,raw) VALUES(?,?,?,?)',
                           (message['id'], now(), 'status_poll', serialized))
            # Aggregate Delivered may refer to only ONE part. Never promote it to full delivery.
            db.execute('''UPDATE messages SET state=?,last_error=NULL,next_check_at=?,delivery_state=CASE
                WHEN ?='Failed' THEN 'failed_or_partial'
                WHEN ?='Delivered' AND delivery_state!='confirmed_all_parts' THEN 'partial_or_unquantified'
                ELSE delivery_state END WHERE id=?''',
                (states[state], (datetime.now(timezone.utc)+timedelta(seconds=3600 if
                    datetime.now(timezone.utc)-datetime.fromisoformat(message['processed_at']) > timedelta(days=1)
                    else 60)).isoformat(), state, state, message['id']))
    except (GatewayError, KeyError, TypeError, ValueError) as exc:
        code = exc.code if isinstance(exc, GatewayError) else 'invalid_status_contract'
        with store.transaction() as db:
            db.execute('UPDATE messages SET last_error=?,next_check_at=? WHERE id=?',
                       (code, (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(), message['id']))


def dispatch_one(store, gateway):
    # Commit an attempt before network submission. A crash after this point is UNKNOWN,
    # never automatically retried. Block/principal/rate limits are checked at dispatch.
    with store.transaction() as db:
        row = db.execute("SELECT * FROM messages WHERE state='queued' ORDER BY seq LIMIT 1").fetchone()
        if not row:
            return
        policy = store.policy(db, row['peer'])
        principal = db.execute('SELECT * FROM principals WHERE id=? AND active=1', (row['origin'],)).fetchone()
        permitted = (principal and 'messages:send' in json.loads(principal['scopes'])
                     and row['peer'] in json.loads(principal['numbers']) and policy['outgoing_allowed'])
        if not permitted:
            db.execute("UPDATE messages SET state='denied',last_error='permission_denied' WHERE id=?", (row['id'],))
            return
        recent = db.execute("SELECT COUNT(*) FROM attempts WHERE started_at>?",
                            ((datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat(),)).fetchone()[0]
        daily = db.execute("SELECT COUNT(*) FROM attempts WHERE started_at>?",
                           ((datetime.now(timezone.utc)-timedelta(days=1)).isoformat(),)).fetchone()[0]
        if recent >= 5 or daily >= 50:
            return
        db.execute("UPDATE messages SET state='submitting',last_error=NULL WHERE id=?", (row['id'],))
        attempt = db.execute("INSERT INTO attempts(message_id,started_at,result) VALUES(?,?,'started')", (row['id'], now())).lastrowid
        message = dict(row)
    # Hold write lock through the bounded POST so a successful block/revoke cannot race
    # ahead of submission. Administrative callers may wait at most the HTTP timeout.
    with store.transaction() as db:
        current = store.policy(db, message['peer'])
        principal = db.execute('SELECT * FROM principals WHERE id=? AND active=1', (message['origin'],)).fetchone()
        if not current['outgoing_allowed'] or not principal:
            db.execute("UPDATE messages SET state='denied' WHERE id=?", (message['id'],))
            db.execute("UPDATE attempts SET result='denied',finished_at=? WHERE id=?", (now(), attempt))
            return
        try:
            response = gateway.send(message)
            if not isinstance(response, dict) or response.get('id') != message['provider_id']:
                raise GatewayError('submission_identity_mismatch')
            state, error = 'submitted', None
            db.execute('INSERT INTO status_observations(message_id,observed_at,source,raw) VALUES(?,?,?,?)',
                       (message['id'], now(), 'submission', json.dumps(response)))
        except (GatewayError, ValueError, TypeError) as exc:
            # Even non-2xx responses are not retried: a proxy/provider may have accepted.
            state, error = 'unknown', exc.code if isinstance(exc, GatewayError) else 'invalid_submission_contract'
        db.execute('UPDATE messages SET state=?,last_error=?,next_check_at=? WHERE id=?', (state, error, now(), message['id']))
        db.execute('UPDATE attempts SET result=?,error=?,finished_at=? WHERE id=?', (state, error, now(), attempt))


def recover_interrupted(store):
    with store.transaction() as db:
        db.execute("UPDATE messages SET state='unknown',last_error='interrupted_submission',next_check_at=? WHERE state='submitting'", (now(),))
        db.execute("UPDATE attempts SET result='unknown',error='interrupted_submission',finished_at=? WHERE result='started'", (now(),))
