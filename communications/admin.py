"""Local OS-authorized administration. No administrative network API."""
import argparse
import contextlib
import json
import os
from pathlib import Path

from .common import atomic_private_json, load_config, now, private_file
from .gateway import Gateway
from .store import Store


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True, help='Private JSON configuration file')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('health')
    sub.add_parser('probe')
    sub.add_parser('initialize-owner')
    contact = sub.add_parser('contact')
    contact.add_argument('--input-file', required=True, help='mode0600 JSON: name, type, notes, id, active')
    number = sub.add_parser('associate')
    number.add_argument('--input-file', required=True, help='mode0600 JSON: contact_id, number')
    block = sub.add_parser('block')
    block.add_argument('--input-file', required=True, help='mode0600 JSON: number, blocked, reason')
    token = sub.add_parser('client')
    token.add_argument('--input-file', required=True, help='mode0600 JSON: id, scopes, numbers')
    token.add_argument('--output-file', required=True, help='private file receiving token, never stdout')
    revoke = sub.add_parser('revoke')
    revoke.add_argument('client_id')
    backup = sub.add_parser('backup')
    backup.add_argument('--directory', help='defaults to private local backups directory')
    verify = sub.add_parser('verify-restore')
    verify.add_argument('--backup', required=True)
    verify.add_argument('--destination', required=True, help='new isolated directory, never live data')
    resolve = sub.add_parser('resolve')
    resolve.add_argument('--input-file', required=True, help='mode0600 JSON: id, outcome, note; no resend')
    args = p.parse_args()
    os.umask(0o077)
    config = load_config(args.config)
    store = Store(Path(config['data_dir']) / 'messages.db')
    value = json.loads(private_file(args.input_file).read_text()) if hasattr(args, 'input_file') else {}
    if args.command == 'health':
        print(json.dumps(store.health()))
    elif args.command == 'probe':
        gateway = Gateway(config)
        result, headers = gateway.request('GET', '/inbox?type=SMS&limit=1')
        # Report schema only: never phone numbers, message bodies, credentials, device IDs.
        print(json.dumps({'inbox_reachable': isinstance(result, list),
                          'row_keys': sorted(result[0]) if result else [],
                          'count_header_present': any(k.lower() == 'x-total-count' for k in headers),
                          'installed_version_reported': bool(config.get('installed_version'))}))
    elif args.command == 'initialize-owner':
        store.owner(config.get('owner_name', 'Owner'), config['owner_number'])
        if config.get('device_number'):
            store.meta('local_number', config['device_number'])
        print('owner_initialized')
    elif args.command == 'contact':
        print(store.contact(value['name'], value.get('type', 'person'), value.get('notes', ''), value.get('id'), value.get('active', True)))
    elif args.command == 'associate':
        store.identifier(value['contact_id'], value['number'])
        print('associated_without_permission_grant')
    elif args.command == 'block':
        if type(value['blocked']) is not bool:
            raise ValueError('blocked_must_be_boolean')
        store.block(value['number'], value['blocked'], value.get('reason', ''))
        print('policy_updated')
    elif args.command == 'client':
        if Path(args.output_file).exists():
            raise ValueError('output_exists')
        token = store.principal(value['id'], value['scopes'], value['numbers'])
        atomic_private_json(args.output_file, {'token': token, 'client_id': value['id']})
        print('client_token_written_privately')
    elif args.command == 'revoke':
        with store.transaction() as db:
            db.execute('UPDATE principals SET active=0 WHERE id=?', (args.client_id,))
        print('client_revoked')
    elif args.command == 'backup':
        target = Path(args.directory) if args.directory else Path(config['data_dir']) / 'backups'
        if not target.resolve().is_relative_to(Path(config['data_dir']).resolve()):
            raise ValueError('backup_must_remain_in_private_data_tree')
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.stat().st_mode & 0o077:
            raise ValueError('private_backup_directory_required')
        name = 'messages-' + now().replace(':', '').replace('+', '_') + '.db'
        store.backup(target / name)
        print(json.dumps({'backup': str(target / name), 'integrity': 'ok', 'offsite': False}))
    elif args.command == 'verify-restore':
        import sqlite3
        source = private_file(args.backup)
        destination = Path(args.destination)
        if destination.exists() or destination.resolve() == Path(config['data_dir']).resolve():
            raise ValueError('fresh_isolated_destination_required')
        if not destination.resolve().is_relative_to(Path(config['data_dir']).resolve()):
            raise ValueError('restore_must_remain_in_private_data_tree')
        destination.mkdir(mode=0o700, parents=True)
        with contextlib.closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as original:
            with contextlib.closing(sqlite3.connect(destination / 'messages.db')) as restored:
                original.backup(restored)
                ok = restored.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                equal = list(original.iterdump()) == list(restored.iterdump())
        if not (ok and equal):
            raise ValueError('restore_verification_failed')
        print(json.dumps({'restore_integrity': 'ok', 'logical_content_equal': True,
                          'isolated': str(destination), 'service_started': False}))
    elif args.command == 'resolve':
        outcome = value['outcome']
        if outcome not in ('operator_confirmed_received', 'operator_confirmed_not_received', 'unresolved'):
            raise ValueError('invalid_resolution')
        with store.transaction() as db:
            row = db.execute("SELECT id FROM messages WHERE id=? AND direction='outgoing'", (value['id'],)).fetchone()
            if not row:
                raise ValueError('unknown_message')
            db.execute('INSERT INTO audit(at,action,subject,detail) VALUES(?,?,?,?)',
                       (now(), 'outbound_manual_resolution', row['id'], json.dumps(value)))
            # Manual resolution is evidence, not a provider delivery receipt or resend.
        print('resolution_recorded_no_resend')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Avoid raw provider/SQLite exceptions containing content or credentials.
        raise SystemExit('administrative_operation_failed:' + type(exc).__name__) from None
