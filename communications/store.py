import contextlib
import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from pathlib import Path

from .common import digest, normalized, now, timestamp

SCHEMA = '''
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS contacts(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identifiers(
 kind TEXT NOT NULL, normalized TEXT NOT NULL, original TEXT NOT NULL,
 contact_id TEXT NOT NULL REFERENCES contacts(id), PRIMARY KEY(kind,normalized));
CREATE TABLE IF NOT EXISTS number_policy(
 number TEXT PRIMARY KEY, incoming_allowed INTEGER NOT NULL DEFAULT 0,
 outgoing_allowed INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
 reason TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS principals(
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL,
 numbers TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS events(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL, transport_id TEXT NOT NULL,
 source TEXT NOT NULL, event_type TEXT NOT NULL, raw TEXT NOT NULL, raw_hash TEXT NOT NULL,
 received_at TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', error TEXT,
 UNIQUE(device,source,transport_id));
CREATE TABLE IF NOT EXISTS messages(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, provider_id TEXT,
 device TEXT, fingerprint TEXT, sender_raw TEXT, recipient_raw TEXT,
 peer TEXT NOT NULL, contact_id TEXT REFERENCES contacts(id), body TEXT NOT NULL,
 content_state TEXT NOT NULL, message_type TEXT NOT NULL DEFAULT 'SMS',
 direction TEXT NOT NULL, original_at TEXT NOT NULL, processed_at TEXT NOT NULL,
 route_state TEXT NOT NULL, state TEXT NOT NULL, delivery_state TEXT NOT NULL DEFAULT 'unconfirmed',
 origin TEXT, idempotency_key TEXT, request_hash TEXT, historical INTEGER NOT NULL DEFAULT 0,
 parts_expected INTEGER, receipts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
 next_check_at TEXT, UNIQUE(origin,idempotency_key));
CREATE INDEX IF NOT EXISTS message_peer ON messages(peer,seq);
CREATE INDEX IF NOT EXISTS message_fingerprint ON messages(fingerprint);
CREATE TABLE IF NOT EXISTS event_messages(
 event_seq INTEGER NOT NULL REFERENCES events(seq), message_id TEXT NOT NULL REFERENCES messages(id),
 PRIMARY KEY(event_seq,message_id));
CREATE TABLE IF NOT EXISTS attempts(
 id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL REFERENCES messages(id),
 started_at TEXT NOT NULL, finished_at TEXT, result TEXT NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS status_observations(
 id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL REFERENCES messages(id),
 observed_at TEXT NOT NULL, source TEXT NOT NULL, raw TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, action TEXT NOT NULL,
 subject TEXT NOT NULL, detail TEXT NOT NULL);
'''


class Denied(Exception):
    pass


class Conflict(Exception):
    pass


class RateLimited(Exception):
    pass


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.umask(0o077)
        with contextlib.closing(self.connect()) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript(SCHEMA)
            db.execute("INSERT OR IGNORE INTO metadata VALUES('schema','1')")
            db.execute("INSERT OR IGNORE INTO metadata VALUES('started_at',?)", (now(),))
            db.commit()
        os.chmod(self.path, 0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        return db

    @contextlib.contextmanager
    def transaction(self):
        with contextlib.closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise

    def meta(self, key, value=None):
        with self.transaction() as db:
            if value is not None:
                db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', (key, value))
            row = db.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
            return row[0] if row else None

    @staticmethod
    def policy(db, number):
        number = normalized(number)
        row = db.execute('''SELECT c.id,c.active FROM identifiers i JOIN contacts c
            ON c.id=i.contact_id WHERE i.kind='phone' AND i.normalized=?''', (number,)).fetchone()
        rule = db.execute('SELECT * FROM number_policy WHERE number=?', (number,)).fetchone()
        blocked = bool(rule and rule['blocked'])
        recognized = bool(row)
        enabled = bool(row and row['active'] and not blocked)
        return dict(number=number, contact_id=row['id'] if row else None,
                    recognized=recognized, blocked=blocked,
                    incoming_allowed=bool(enabled and rule and rule['incoming_allowed']),
                    outgoing_allowed=bool(enabled and rule and rule['outgoing_allowed']),
                    sensitive_action_verified=False)

    def contact(self, name, kind='person', notes='', contact_id=None, active=True):
        if not isinstance(name, str) or not 1 <= len(name) <= 200 or len(notes) > 4000:
            raise ValueError('invalid_contact')
        ident = contact_id or str(uuid.uuid4())
        with self.transaction() as db:
            db.execute('''INSERT INTO contacts VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,type=excluded.type,notes=excluded.notes,active=excluded.active''',
                       (ident, name, kind, notes, int(active), now()))
        return ident

    def identifier(self, contact, original):
        number = normalized(original)
        with self.transaction() as db:
            db.execute("INSERT INTO identifiers VALUES('phone',?,?,?)", (number, original, contact))
            db.execute('UPDATE messages SET contact_id=? WHERE peer=?', (contact, number))
            # Association alone never grants communication permissions or replays history.
        return number

    def owner(self, name, number):
        match = normalized(number)
        if not match.startswith('+'):
            raise ValueError('owner_requires_international_number')
        with self.transaction() as db:
            existing = db.execute("SELECT value FROM metadata WHERE key='owner_number'").fetchone()
            if existing:
                if existing[0] != match:
                    raise Conflict('owner_already_provisioned')
                return self.policy(db, match)['contact_id']
            ident = str(uuid.uuid4())
            db.execute('INSERT INTO contacts VALUES(?,?,?,?,1,?)', (ident, name, 'owner', '', now()))
            db.execute("INSERT INTO identifiers VALUES('phone',?,?,?)", (match, number, ident))
            db.execute('''INSERT INTO number_policy VALUES(?,1,1,0,'',?)
                ON CONFLICT(number) DO UPDATE SET incoming_allowed=1,outgoing_allowed=1''', (match, now()))
            db.execute("INSERT INTO metadata VALUES('owner_number',?)", (match,))
            db.execute('UPDATE messages SET contact_id=? WHERE peer=?', (ident, match))
            return ident

    def block(self, number, blocked, reason=''):
        number = normalized(number)
        with self.transaction() as db:
            db.execute('''INSERT INTO number_policy(number,blocked,reason,updated_at) VALUES(?,?,?,?)
                ON CONFLICT(number) DO UPDATE SET blocked=excluded.blocked,reason=excluded.reason,
                updated_at=excluded.updated_at''', (number, int(blocked), reason[:2000], now()))
            db.execute('INSERT INTO audit(at,action,subject,detail) VALUES(?,?,?,?)',
                       (now(), 'block' if blocked else 'unblock', number, reason[:2000]))

    def principal(self, ident, scopes, numbers):
        allowed = {'messages:read', 'contacts:read', 'permissions:read', 'messages:send', 'status:read', 'health:read'}
        if not set(scopes) <= allowed or not scopes:
            raise ValueError('invalid_scopes')
        token = secrets.token_urlsafe(32)
        with self.transaction() as db:
            db.execute('INSERT INTO principals VALUES(?,?,?,?,1)',
                       (ident, hashlib.sha256(token.encode()).hexdigest(), json.dumps(scopes),
                        json.dumps([normalized(n) for n in numbers])))
        return token

    def authenticate(self, token):
        if not isinstance(token, str) or not 20 <= len(token) <= 200:
            raise Denied('unauthorized')
        with contextlib.closing(self.connect()) as db:
            row = db.execute('SELECT * FROM principals WHERE token_hash=? AND active=1',
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if not row:
                raise Denied('unauthorized')
            return {**dict(row), 'scopes': json.loads(row['scopes']), 'numbers': json.loads(row['numbers'])}

    @staticmethod
    def require(principal, scope, number=None):
        if scope not in principal['scopes'] or (number is not None and normalized(number) not in principal['numbers']):
            raise Denied('forbidden')

    def intake(self, device, transport_id, source, event_type, raw):
        serialized = json.dumps(raw, ensure_ascii=False, sort_keys=True)
        hashed = digest(raw)
        with self.transaction() as db:
            old = db.execute('SELECT seq,raw_hash FROM events WHERE device=? AND source=? AND transport_id=?',
                             (device, source, transport_id)).fetchone()
            if old:
                if old['raw_hash'] != hashed:
                    # Preserve conflicting observations rather than overwrite or silently discard.
                    transport_id += ':conflict:' + hashed
                    event_type = 'identity_conflict'
                else:
                    return old['seq']
            db.execute('''INSERT OR IGNORE INTO events(device,transport_id,source,event_type,raw,raw_hash,received_at)
                VALUES(?,?,?,?,?,?,?)''', (device, transport_id, source, event_type, serialized, hashed, now()))
            return db.execute('SELECT seq FROM events WHERE device=? AND source=? AND transport_id=?',
                              (device, source, transport_id)).fetchone()[0]

    def process_events(self):
        with self.transaction() as db:
            rows = db.execute("SELECT * FROM events WHERE state='pending' ORDER BY seq LIMIT 100").fetchall()
            start = db.execute("SELECT value FROM metadata WHERE key='started_at'").fetchone()[0]
            for event in rows:
                try:
                    raw = json.loads(event['raw'])
                    if event['event_type'] == 'sms:received':
                        self._incoming(db, event, raw, start)
                    elif event['event_type'] in ('sms:sent', 'sms:delivered', 'sms:failed'):
                        self._receipt(db, event, raw)
                    else:
                        raise ValueError('unsupported_or_conflicting_event')
                    db.execute("UPDATE events SET state='processed' WHERE seq=?", (event['seq'],))
                except (ValueError, KeyError, TypeError):
                    db.execute("UPDATE events SET state='quarantined',error='invalid_payload' WHERE seq=?", (event['seq'],))

    def _incoming(self, db, event, raw, start):
        p = raw['payload']
        sender, recipient = p['sender'], p.get('recipient')
        peer = normalized(sender)
        if recipient is not None:
            normalized(recipient)
        body = p['message']
        if not isinstance(body, str) or len(body.encode()) > 131072:
            raise ValueError('invalid_body')
        date = timestamp(p['receivedAt'])
        fingerprint = digest([event['device'], sender, recipient, p.get('simNumber'), date, body])
        previous = db.execute('SELECT * FROM messages WHERE fingerprint=? ORDER BY seq', (fingerprint,)).fetchall()
        # Poll observations have no occurrence ID beyond the observable tuple. Link them
        # to webhook observations when possible; never collapse distinct webhook envelopes.
        matching = previous and (event['source'] == 'poll' or all(r['origin'] == 'poll' for r in previous))
        if matching:
            message_id = previous[0]['id']
            if raw.get('fullBodyVerified'):
                db.execute("""UPDATE messages SET content_state='complete_verified',
                    historical=CASE WHEN route_state='incomplete_content' THEN 1 ELSE historical END,
                    route_state=CASE WHEN route_state='incomplete_content' THEN 'historical' ELSE route_state END
                    WHERE id=?""", (message_id,))
        else:
            policy = self.policy(db, sender)
            historical = date < start or bool(raw.get('historical'))
            complete = event['source'] == 'webhook' or bool(raw.get('fullBodyVerified'))
            route = ('historical' if historical else 'blocked' if policy['blocked'] else
                     'permitted' if policy['incoming_allowed'] else 'unauthorized')
            if not complete:
                route = 'incomplete_content'
            if previous:
                route = 'ambiguous_identity'
            message_id = str(uuid.uuid4())
            db.execute('''INSERT INTO messages(id,provider_id,device,fingerprint,sender_raw,recipient_raw,
                peer,contact_id,body,content_state,direction,original_at,processed_at,route_state,state,origin,historical)
                VALUES(?,?,?,?,?,?,?,?,?,?,'incoming',?,?,?,'recorded',?,?)''',
                (message_id, p.get('messageId'), event['device'], fingerprint, sender, recipient,
                 peer, policy['contact_id'], body, 'complete_verified' if complete else 'preview_unverified',
                 date, now(), route, event['source'], int(historical)))
        db.execute('INSERT OR IGNORE INTO event_messages VALUES(?,?)', (event['seq'], message_id))

    def _receipt(self, db, event, raw):
        p = raw['payload']
        row = db.execute("SELECT * FROM messages WHERE provider_id=? AND direction='outgoing'",
                         (p['messageId'],)).fetchone()
        if not row:
            # Retain authenticated out-of-scope status events, but do not invent message bodies.
            return
        if normalized(p.get('recipient') or p.get('phoneNumber')) != row['peer']:
            raise ValueError('recipient_mismatch')
        db.execute('INSERT INTO status_observations(message_id,observed_at,source,raw) VALUES(?,?,?,?)',
                   (row['id'], now(), 'webhook', event['raw']))
        kind = event['event_type']
        if kind == 'sms:sent':
            parts = p['partsCount']
            if type(parts) is not int or not 1 <= parts <= 1000:
                raise ValueError('invalid_parts')
            db.execute("UPDATE messages SET parts_expected=?,state=CASE WHEN state='failed' THEN state ELSE 'sent' END WHERE id=?",
                       (parts, row['id']))
        elif kind == 'sms:delivered':
            db.execute('UPDATE messages SET receipts=receipts+1 WHERE id=?', (row['id'],))
        elif kind == 'sms:failed':
            db.execute("UPDATE messages SET state='failed',delivery_state='failed_or_partial',last_error='provider_failed' WHERE id=?", (row['id'],))
        db.execute('''UPDATE messages SET delivery_state=CASE
            WHEN state='failed' THEN 'failed_or_partial'
            WHEN parts_expected IS NOT NULL AND receipts>=parts_expected THEN 'confirmed_all_parts'
            WHEN receipts>0 THEN 'partial_or_unquantified' ELSE delivery_state END WHERE id=?''', (row['id'],))
        db.execute('INSERT OR IGNORE INTO event_messages VALUES(?,?)', (event['seq'], row['id']))

    def enqueue(self, principal, recipient, body, key):
        peer = normalized(recipient)
        self.require(principal, 'messages:send', peer)
        if not isinstance(body, str) or not 1 <= len(body) <= 4000 or not isinstance(key, str) or not 8 <= len(key) <= 128:
            raise ValueError('invalid_outbound_request')
        request_hash = digest([peer, body])
        with self.transaction() as db:
            old = db.execute('SELECT * FROM messages WHERE origin=? AND idempotency_key=?', (principal['id'], key)).fetchone()
            if old:
                if old['request_hash'] != request_hash:
                    raise Conflict('idempotency_key_reused')
                return old['id']
            policy = self.policy(db, peer)
            pending = db.execute("SELECT COUNT(*) FROM messages WHERE state='queued'").fetchone()[0]
            if pending >= 50:
                raise RateLimited('queue_limit')
            state = 'queued' if policy['outgoing_allowed'] else 'denied'
            mid = str(uuid.uuid4())
            db.execute('''INSERT INTO messages(id,provider_id,recipient_raw,peer,contact_id,body,content_state,
                direction,original_at,processed_at,route_state,state,origin,idempotency_key,request_hash)
                VALUES(?,?,?,?,?,?,'complete_verified','outgoing',?,?,'outbound',?,?,?,?)''',
                (mid, 'comm-' + mid, recipient, peer, policy['contact_id'], body, now(), now(), state,
                 principal['id'], key, request_hash))
            local_number = db.execute("SELECT value FROM metadata WHERE key='local_number'").fetchone()
            if local_number:
                db.execute('UPDATE messages SET sender_raw=? WHERE id=?', (local_number[0], mid))
            return mid

    def history(self, principal, after=0, limit=100):
        self.require(principal, 'messages:read')
        with contextlib.closing(self.connect()) as db:
            # Read policy is evaluated now, not from the historical routing result.
            permitted = [n for n in principal['numbers'] if self.policy(db, n)['incoming_allowed']]
            if not permitted:
                return []
            slots = ','.join('?' for _ in permitted)
            rows = db.execute(f'''SELECT * FROM messages WHERE seq>? AND peer IN ({slots})
                AND content_state='complete_verified' AND route_state!='ambiguous_identity'
                ORDER BY seq LIMIT ?''', (after, *permitted, min(max(limit, 1), 200))).fetchall()
            return [dict(r) for r in rows]

    def health(self):
        with contextlib.closing(self.connect()) as db:
            return {'database': 'ok' if db.execute('PRAGMA quick_check').fetchone()[0] == 'ok' else 'error',
                    'events_pending': db.execute("SELECT COUNT(*) FROM events WHERE state='pending'").fetchone()[0],
                    'events_quarantined': db.execute("SELECT COUNT(*) FROM events WHERE state='quarantined'").fetchone()[0],
                    'outbound_unknown': db.execute("SELECT COUNT(*) FROM messages WHERE state='unknown'").fetchone()[0],
                    'agent_execution': False}

    def backup(self, destination):
        target = Path(destination)
        if target.exists():
            raise ValueError('backup_destination_exists')
        with contextlib.closing(self.connect()) as source, contextlib.closing(sqlite3.connect(target)) as dest:
            source.backup(dest)
            if dest.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('backup_integrity_failed')
        os.chmod(target, 0o600)
        return target
