import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('invalid_timestamp')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timezone_required')
    return parsed.astimezone(timezone.utc).isoformat(timespec='milliseconds')


def normalized(value):
    """Require an explicit country code; national and short identifiers remain opaque."""
    if not isinstance(value,str) or not 1<=len(value)<=128:raise ValueError('invalid_identifier')
    compact=re.sub(r'[ ()\-.]','',value.strip())
    if re.fullmatch(r'\+[1-9][0-9]{1,14}',compact):return compact
    return 'raw:'+value.strip()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def private_file(path):
    path = Path(path)
    st = path.stat()
    if path.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError('private_file_permissions_required')
    return path


def poll_interval(config):
    value = config.get('poll_seconds', 60)
    if type(value) is not int or not 10 <= value <= 3600:
        raise ValueError('invalid_poll_seconds')
    return value


def load_config(path):
    from .configuration import validate_config
    return validate_config(json.loads(private_file(path).read_text()))


def atomic_private_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
