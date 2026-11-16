import argparse
import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import signal
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .common import load_config, now, private_file, poll_interval
from .gateway import Gateway, GatewayError, dispatch_one, reconcile, recover_interrupted
from .store import Conflict, Denied, RateLimited, Store


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True
    request_queue_size = 16

    def __init__(self, address, store, config, webhook_only=False):
        self.store, self.config, self.webhook_only = store, config, webhook_only
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Python's default handler would log request details/tracebacks.
        print('http_request_error', flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = 'AgentSMSBridge/0.1'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, *_):
        pass

    def response(self, code, payload):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        for key, value in {'Content-Type': 'application/json', 'Content-Length': str(len(data)),
                'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                'Connection': 'close'}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            raise ValueError('content_length_required')
        length = int(self.headers['Content-Length'])
        if not 1 <= length <= 262144 or self.headers.get_content_type() != 'application/json':
            raise ValueError('invalid_body')
        data = self.rfile.read(length)
        if len(data) != length:
            raise ValueError('incomplete_body')
        return data

    def do_GET(self):
        self.handle_route('GET')

    def do_POST(self):
        self.handle_route('POST')

    def handle_route(self, method):
        try:
            if len(self.path) > 2048 or self.headers.get('Origin'):
                raise Denied('forbidden')
            parts = urllib.parse.urlsplit(self.path)
            if parts.scheme or parts.netloc or parts.fragment:
                raise ValueError('invalid_path')
            if self.server.webhook_only:
                if parts.path != '/webhooks/smsgate' or parts.query or method != 'POST':
                    self.response(404, {'error': 'not_found'})
                    return
                self.webhook()
                return
            if len(self.headers.get_all('Authorization', [])) != 1:
                raise Denied('unauthorized')
            auth = self.headers['Authorization']
            if not auth.startswith('Bearer '):
                raise Denied('unauthorized')
            store = self.server.store
            principal = store.authenticate(auth[7:])
            query = urllib.parse.parse_qs(parts.query, strict_parsing=True)
            if method == 'GET' and parts.path == '/v1/health':
                store.require(principal, 'health:read')
                data = store.health()
                data.update(gateway_configured=bool(self.server.config.get('gateway_url')),
                            full_body_verified=bool(self.server.config.get('inbox_full_body_verified')),
                            last_poll_ok=store.meta('last_poll_ok'), last_poll_error=store.meta('last_poll_error'))
            elif method == 'GET' and parts.path == '/v1/messages':
                if set(query) - {'after', 'limit'}:
                    raise ValueError('invalid_query')
                data = {'messages': store.history(principal, int(query.get('after', ['0'])[0]), int(query.get('limit', ['100'])[0]))}
            elif method == 'GET' and parts.path == '/v1/permissions':
                if set(query) != {'number'} or len(query['number']) != 1:
                    raise ValueError('number_required')
                number = query['number'][0]
                store.require(principal, 'permissions:read', number)
                with contextlib.closing(store.connect()) as db:
                    data = store.policy(db, number)
            elif method == 'GET' and parts.path == '/v1/contacts':
                store.require(principal, 'contacts:read')
                with contextlib.closing(store.connect()) as db:
                    data = []
                    for number in principal['numbers']:
                        policy = store.policy(db, number)
                        if policy['incoming_allowed']:
                            contact = db.execute('SELECT * FROM contacts WHERE id=?', (policy['contact_id'],)).fetchone()
                            data.append({'id': contact['id'], 'name': contact['name'], 'type': contact['type'], 'number': number})
            elif method == 'GET' and parts.path.startswith('/v1/messages/'):
                store.require(principal, 'status:read')
                ident = parts.path.removeprefix('/v1/messages/')
                with contextlib.closing(store.connect()) as db:
                    row = db.execute("SELECT * FROM messages WHERE id=? AND direction='outgoing' AND origin=?", (ident, principal['id'])).fetchone()
                    if not row:
                        raise Denied('forbidden')
                    store.require(principal, 'status:read', row['peer'])
                    # Status is limited to caller's own operation; no body/number exposure.
                    data = {k: row[k] for k in ('id','state','delivery_state','parts_expected','receipts','last_error')}
                    data['attempts'] = db.execute('SELECT COUNT(*) FROM attempts WHERE message_id=?', (ident,)).fetchone()[0]
            elif method == 'POST' and parts.path == '/v1/messages' and not parts.query:
                value = strict_json(self.body())
                if not isinstance(value, dict) or set(value) != {'recipient', 'body', 'idempotency_key'}:
                    raise ValueError('invalid_request_fields')
                ident = store.enqueue(principal, value['recipient'], value['body'], value['idempotency_key'])
                self.response(202, {'id': ident})
                return
            else:
                self.response(404, {'error': 'not_found'})
                return
            self.response(200, data)
        except Denied as exc:
            self.response(401 if str(exc) == 'unauthorized' else 403, {'error': str(exc)})
        except Conflict:
            self.response(409, {'error': 'conflict'})
        except RateLimited:
            self.response(429, {'error': 'rate_limited'})
        except (ValueError, KeyError, TypeError, UnicodeError):
            self.response(400, {'error': 'invalid_request'})
        except (BrokenPipeError, ConnectionError, TimeoutError):
            pass
        except Exception:
            self.response(503, {'error': 'temporarily_unavailable'})

    def webhook(self):
        config = self.server.config
        if self.client_address[0] not in config.get('webhook_source_ips', []):
            raise Denied('forbidden')
        raw = self.body()
        stamp = self.headers.get('X-Timestamp', '')
        signature = self.headers.get('X-Signature', '')
        if not stamp.isdecimal() or abs(time.time() - int(stamp)) > 300:
            raise Denied('forbidden')
        expected = hmac.new(config['webhook_signing_key'].encode(), raw + stamp.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise Denied('forbidden')
        event = strict_json(raw)
        if not isinstance(event, dict) or event.get('deviceId') != config.get('device_id'):
            raise Denied('forbidden')
        if event.get('webhookId') not in config.get('webhook_ids', []):
            raise Denied('forbidden')
        if not isinstance(event.get('id'), str) or not 1 <= len(event['id']) <= 200:
            raise ValueError('invalid_event_identity')
        if event.get('event') not in ('sms:received', 'sms:sent', 'sms:delivered', 'sms:failed'):
            raise ValueError('unsupported_event')
        self.server.store.intake(event['deviceId'], event['id'], 'webhook', event['event'], event)
        # Durable commit above is the acknowledgement boundary; routing is asynchronous.
        self.response(202, {'accepted': True})


def worker(store, config, stop):
    gateway = Gateway(config) if config.get('gateway_url') else None
    interval = poll_interval(config)
    poll_at = 0
    while not stop.is_set():
        try:
            store.process_events()
            if gateway and time.monotonic() >= poll_at:
                try:
                    gateway.poll(store)
                    store.meta('last_poll_error', '')
                except (GatewayError, ValueError, KeyError, TypeError) as exc:
                    store.meta('last_poll_error', exc.code if isinstance(exc, GatewayError) else 'invalid_poll_contract')
                poll_at = time.monotonic() + interval
            if gateway and config.get('outbound_enabled', False):
                dispatch_one(store, gateway)
            if gateway:
                with contextlib.closing(store.connect()) as db:
                    rows = db.execute("""SELECT * FROM messages WHERE direction='outgoing'
                        AND state IN ('unknown','submitted','processed_unconfirmed','sent')
                        AND (next_check_at IS NULL OR next_check_at<=?) ORDER BY seq LIMIT 10""", (now(),)).fetchall()
                for row in rows:
                    if stop.is_set():
                        break
                    reconcile(store, gateway, row)
        except Exception:
            print('worker_cycle_failed', flush=True)
        stop.wait(2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    config = load_config(args.config)
    root = Path(config['data_dir'])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = open(root / 'service.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    store = Store(root / 'messages.db')
    recover_interrupted(store)
    stop = threading.Event()
    servers = [Server(('127.0.0.1', config.get('api_port', 4190)), store, config)]
    if config.get('webhook_enabled'):
        address = ipaddress.ip_address(config['webhook_bind'])
        if address.is_unspecified or not (address.is_private or address in ipaddress.ip_network('100.64.0.0/10')):
            raise ValueError('private_webhook_bind_required')
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(config['tls_cert'], private_file(config['tls_key']))
        server = Server((str(address), config.get('webhook_port', 4191)), store, config, webhook_only=True)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        servers.append(server)
    threads = []
    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    worker_thread = threading.Thread(target=worker, args=(store, config, stop), daemon=True)
    worker_thread.start()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print('communications_started', flush=True)
    stop.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    worker_thread.join(timeout=45)
    if worker_thread.is_alive():
        print('shutdown_incomplete_attempt_reconciles_on_restart', flush=True)
    print('communications_stopped', flush=True)


if __name__ == '__main__':
    main()
