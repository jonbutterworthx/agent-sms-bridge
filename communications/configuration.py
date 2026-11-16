"""Shared validation for private JSON configuration and initial setup."""
import argparse
import json
import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit
from .common import atomic_private_json, normalized, private_file, poll_interval


def validate_config(value):
    if not isinstance(value,dict):raise ValueError('configuration_object_required')
    config=dict(value)
    root=Path(config.get('data_dir',''))
    if not root.is_absolute() or '..' in root.parts or root==Path('/'):
        raise ValueError('absolute_private_data_directory_required')
    for directory in [*root.parents,root]:
        if directory.is_symlink():raise ValueError('symlink_storage_refused')
    if root.exists() and (root.stat().st_uid!=os.getuid() or root.stat().st_mode&0o077):
        raise ValueError('private_directory_required')
    for key,low,high,default in [('api_port',1024,65535,4190)]:
        v=config.get(key,default)
        if type(v) is not int or not low<=v<=high:raise ValueError('invalid_'+key)
        config[key]=v
    config['poll_seconds']=poll_interval(config)
    for key in ('outbound_enabled','inbox_full_body_verified','webhook_enabled'):
        if type(config.get(key,False)) is not bool:raise ValueError('invalid_'+key)
    if config.get('webhook_enabled'):raise ValueError('webhooks_not_supported_in_release_candidate')
    url=config.get('gateway_url')
    if url:
        try:
            parts=urlsplit(url);address=ipaddress.ip_address(parts.hostname or '')
            if parts.scheme not in ('http','https') or parts.username or parts.password or parts.path not in ('','/') or parts.query or parts.fragment:
                raise ValueError()
            private=address.is_private or address in ipaddress.ip_network('100.64.0.0/10')
            if not private or address.is_unspecified or address.is_multicast or address.is_link_local:
                raise ValueError()
            if parts.port is not None and not 1<=parts.port<=65535:raise ValueError()
        except (ValueError,TypeError):raise ValueError('private_gateway_ip_url_required') from None
        for key in ('gateway_username','gateway_password'):
            v=config.get(key)
            if not isinstance(v,str) or not 1<=len(v)<=2048 or '\n' in v or '\r' in v or '\x00' in v:
                raise ValueError('invalid_gateway_credentials')
        if ':' in config['gateway_username']:raise ValueError('invalid_gateway_credentials')
        config['gateway_url']=url.rstrip('/')
    elif config.get('outbound_enabled'):raise ValueError('gateway_required_for_outbound')
    for key in ('owner_number','device_number'):
        if config.get(key) and not normalized(config[key]).startswith('+'):
            raise ValueError('explicit_international_number_required')
    if config.get('inbox_full_body_verified') and not config.get('inbox_verification_evidence'):
        raise ValueError('full_body_verification_reference_required')
    return config


def validate_initial(value,root):
    keys={'gateway_url','gateway_username','gateway_password','installed_version','owner_name','owner_number','device_number'}
    if not isinstance(value,dict) or set(value)!=keys or any(not isinstance(x,str) for x in value.values()):
        raise ValueError('complete_setup_fields_required')
    if not value['gateway_url'] or not value['owner_number'] or len(value['owner_name'])>100 or len(value['installed_version'])>100:
        raise ValueError('invalid_setup_fields')
    return validate_config({**value,'owner_name':value['owner_name'].strip() or 'Owner',
        'owner_number':normalized(value['owner_number']),'device_number':normalized(value['device_number']) if value['device_number'] else None,
        'data_dir':str(root),'api_port':4190,'poll_seconds':60,'device_id':'local-sms-device',
        'outbound_enabled':False,'inbox_full_body_verified':False,'inbox_verification_evidence':'','webhook_enabled':False})


def private_directory(root):
    root=Path(root)
    if not root.is_absolute() or '..' in root.parts:raise ValueError('absolute_private_data_directory_required')
    for p in [*reversed(root.parents),root]:
        if p.is_symlink():raise ValueError('symlink_storage_refused')
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if root.stat().st_uid!=os.getuid() or root.stat().st_mode&0o077:
        raise ValueError('private_directory_required')
    return root


def save_initial(root,value):
    from .store import Store
    root=private_directory(root)
    if (root/'config.json').exists():raise ValueError('configuration_already_exists')
    config=validate_initial(value,root)
    # Exclusive claim survives crashes: never overwrite config or replay initialization silently.
    lock=os.open(root/'setup.claim',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(lock)
    atomic_private_json(root/'config.json',config)
    store=Store(root/'messages.db');store.owner(config['owner_name'],config['owner_number'])
    if config.get('device_number'):store.meta('local_number',config['device_number'])
    return config


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True,help='Private JSON initial-setup fields')
    p.add_argument('--data-dir',type=Path,required=True)
    p.add_argument('--apply',action='store_true',help='Without this, validate only')
    args=p.parse_args();os.umask(0o077)
    value=json.loads(private_file(args.input).read_text())
    validate_initial(value,args.data_dir)
    if args.apply:save_initial(args.data_dir,value)
    print('configuration_saved_outbound_disabled' if args.apply else 'configuration_valid_no_write')

if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('configuration_failed:'+type(e).__name__) from None
