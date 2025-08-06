"""Common Utils."""
import ast
import base64
import hashlib
import io
import json
import logging
import ntpath
import os
import platform
import random
import re
import sys
import shutil
import string

import socket
import unicodedata
from urllib.parse import urlparse
from pathlib import Path


logger = logging.getLogger(__name__)
logging.getLogger("androguard").disabled = True
ADB_PATH = None
BASE64_REGEX = re.compile(r'^[-A-Za-z0-9+/]*={0,3}$')
MD5_REGEX = re.compile(r'^[0-9a-f]{32}$')
# Regex to capture strings between quotes or <string> tag
STRINGS_REGEX = re.compile(r'(?<=\")(.+?)(?=\")|(?<=\<string>)(.+?)(?=\<)')
# MobSF Custom regex to catch maximum URI like strings
URL_REGEX = re.compile(
    (
        r'((?:https?://|s?ftps?://|'
        r'file://|javascript:|data:|www\d{0,3}[.])'
        r'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
    ),
    re.UNICODE)
EMAIL_REGEX = re.compile(r'[\w+.-]{1,20}@[\w-]{1,20}\.[\w]{2,10}')
USERNAME_REGEX = re.compile(r'^\w[\w\-\@\.]{1,35}$')
GOOGLE_API_KEY_REGEX = re.compile(r'AIza[0-9A-Za-z-_]{35}$')
GOOGLE_APP_ID_REGEX = re.compile(r'\d{1,2}:\d{1,50}:android:[a-f0-9]{1,50}')
PKG_REGEX = re.compile(
    r'package\s+([a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*);')


class Color(object):
    GREEN = '\033[92m'
    GREY = '\033[0;37m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


# for now it is just a dummy - maybe used in future sandroid releases
def find_java_binary():
    return None

"""
def find_java_binary():
    # Find Java.
    # Respect user settings
    if platform.system() == 'Windows':
        jbin = 'java.exe'
    else:
        jbin = 'java'
    if is_dir_exists(settings.JAVA_DIRECTORY):
        if settings.JAVA_DIRECTORY.endswith('/'):
            return settings.JAVA_DIRECTORY + jbin
        elif settings.JAVA_DIRECTORY.endswith('\\'):
            return settings.JAVA_DIRECTORY + jbin
        else:
            return settings.JAVA_DIRECTORY + '/' + jbin
    if os.getenv('JAVA_HOME'):
        java = os.path.join(
            os.getenv('JAVA_HOME'),
            'bin',
            jbin)
        if is_file_exists(java):
            return java
    return 'java'
"""




def filename_from_path(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def get_md5(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ''


def is_number(s):
    if not s:
        return False
    if s == 'NaN':
        return False
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False


def python_list(value):
    if not value:
        value = []
    if isinstance(value, list):
        return value
    return ast.literal_eval(value)


def python_dict(value):
    if not value:
        value = {}
    if isinstance(value, dict):
        return value
    return ast.literal_eval(value)


def is_base64(b_str):
    return BASE64_REGEX.match(b_str)




def sha256(file_path):
    blocksize = 65536
    hasher = hashlib.sha256()
    with io.open(file_path, mode='rb') as afile:
        buf = afile.read(blocksize)
        while buf:
            hasher.update(buf)
            buf = afile.read(blocksize)
    return hasher.hexdigest()


def sha256_object(file_obj):
    blocksize = 65536
    hasher = hashlib.sha256()
    buf = file_obj.read(blocksize)
    while buf:
        hasher.update(buf)
        buf = file_obj.read(blocksize)
    return hasher.hexdigest()


def gen_sha256_hash(msg):
    """Generate SHA 256 Hash of the message."""
    if isinstance(msg, str):
        msg = msg.encode('utf-8')
    hash_object = hashlib.sha256(msg)
    return hash_object.hexdigest()


def is_file_exists(file_path):
    if os.path.isfile(file_path):
        return True
    # This fix situation where a user just typed "adb" or another executable
    # inside settings.py/config.py
    if shutil.which(file_path):
        return True
    else:
        return False


def is_dir_exists(dir_path):
    if os.path.isdir(dir_path):
        return True
    else:
        return False



def is_safe_path(safe_root, check_path):
    """Detect Path Traversal."""
    safe_root = os.path.realpath(os.path.normpath(safe_root))
    check_path = os.path.realpath(os.path.normpath(check_path))
    return os.path.commonprefix([check_path, safe_root]) == safe_root


def file_size(app_path):
    """Return the size of the file."""
    return round(float(os.path.getsize(app_path)) / (1024 * 1024), 2)


def is_md5(user_input):
    """Check if string is valid MD5."""
    stat = MD5_REGEX.match(user_input)
    if not stat:
        logger.error('Invalid scan hash')
    return stat




def clean_filename(filename, replace=' '):
    if platform.system() == 'Windows':
        whitelist = f'-_.() {string.ascii_letters}{string.digits}'
        # replace spaces
        for r in replace:
            filename = filename.replace(r, '_')
        # keep only valid ascii chars
        cleaned_filename = unicodedata.normalize(
            'NFKD', filename).encode('ASCII', 'ignore').decode()
        # keep only whitelisted chars
        return ''.join(c for c in cleaned_filename if c in whitelist)
    return filename


def cmd_injection_check(data):
    """OS Cmd Injection from Commix."""
    breakers = [
        ';', '%3B', '&', '%26', '&&',
        '%26%26', '|', '%7C', '||',
        '%7C%7C', '%0a', '%0d%0a',
    ]
    return any(i in data for i in breakers)


def strict_package_check(user_input):
    """Strict package name check.

    For android package and ios bundle id
    """
    pat = re.compile(r'^([a-zA-Z]{1}[\w.-]{1,255})$')
    resp = re.match(pat, user_input)
    if not resp or '..' in user_input:
        logger.error('Invalid package name/bundle id/class name')
    return resp


def strict_ios_class(user_input):
    """Strict check to see if input is valid iOS class."""
    pat = re.compile(r'^([\w\.]+)$')
    resp = re.match(pat, user_input)
    if not resp:
        logger.error('Invalid class name')
    return resp


def is_instance_id(user_input):
    """Check if string is valid instance id."""
    reg = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    stat = re.match(reg, user_input)
    if not stat:
        logger.error('Invalid instance identifier')
    return stat


def common_check(instance_id):
    """Common checks for instance APIs."""
    
    if not is_instance_id(instance_id):
        return {
            'status': 'failed',
            'message': 'Invalid instance identifier'}
    else:
        return None


def is_path_traversal(user_input):
    """Check for path traversal."""
    if (('../' in user_input)
        or ('%2e%2e' in user_input)
        or ('..' in user_input)
            or ('%252e' in user_input)):
        logger.error('Path traversal attack detected')
        return True
    return False


def is_zip_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    # ZIP magic PK.. no support for spanned and empty arch
    return bool(magic == b'\x50\x4B\x03\x04')


def is_elf_so_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    # ELF/SO Magic
    return bool(magic == b'\x7F\x45\x4C\x46')


def is_dylib_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    # DYLIB Magic
    magics = (
        b'\xCA\xFE\xBA\xBE',  # 32 bit
        b'\xFE\xED\xFA\xCE',  # 32 bit
        b'\xCE\xFA\xED\xFE',  # 32 bit
        b'\xFE\xED\xFA\xCF',  # 64 bit
        b'\xCF\xFA\xED\xFE',  # 64 bit
        b'\xCA\xFE\xBA\xBF',  # 64 bit
    )
    return bool(magic in magics)


def is_a_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    magics = (
        b'\x21\x3C\x61\x72',
        b'\xCA\xFE\xBA\xBF',  # 64 bit
        b'\xCA\xFE\xBA\xBE',  # 32 bit
    )
    return bool(magic in magics)


def disable_print():
    sys.stdout = open(os.devnull, 'w')


# Restore
def enable_print():
    sys.stdout = sys.__stdout__


def find_key_in_dict(key, var):
    """Recursively look up a key in a nested dict."""
    if hasattr(var, 'items'):
        for k, v in var.items():
            if k == key:
                yield v
            if isinstance(v, dict):
                for result in find_key_in_dict(key, v):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in find_key_in_dict(key, d):
                        yield result


def key(data, key_name):
    """Return the data for a key_name."""
    return data.get(key_name)


def replace(value, arg):
    """
    Replacing filter.

    Use `{{ "aaa"|replace:"a|b" }}`
    """
    if len(arg.split('|')) != 2:
        return value

    what, to = arg.split('|')
    return value.replace(what, to)


def pathify(value):
    """Convert to path."""
    return value.replace('.', '/')


def relative_path(value):
    """Show relative path to two parents."""
    sep = None
    if '/' in value:
        sep = '/'
    elif '\\\\' in value:
        sep = '\\\\'
    elif '\\' in value:
        sep = '\\'
    if not sep or value.count(sep) < 2:
        return value
    path = Path(value)
    return path.relative_to(path.parent.parent).as_posix()


def pretty_json(value):
    """Pretty print JSON."""
    try:
        return json.dumps(json.loads(value), indent=4)
    except Exception:
        return value


def base64_decode(value):
    """Try Base64 decode."""
    commonb64s = ('eyJ0')
    decoded = None
    try:
        if is_base64(value) or value.startswith(commonb64s):
            decoded = base64.b64decode(
                value).decode('ISO-8859-1')
    except Exception:
        pass
    if decoded:
        return f'{value}\n\nBase64 Decoded: {decoded}'
    return value


def base64_encode(value):
    """Base64 encode."""
    if isinstance(value, str):
        value = value.encode('utf-8')
    return base64.b64encode(value)


def android_component(data):
    """Return Android component from data."""
    cmp = ''
    if 'Activity-Alias' in data:
        cmp = 'activity_alias_'
    elif 'Activity' in data:
        cmp = 'activity_'
    elif 'Service' in data:
        cmp = 'service_'
    elif 'Content Provider' in data:
        cmp = 'provider_'
    elif 'Broadcast Receiver' in data:
        cmp = 'receiver_'
    return cmp


def get_android_dm_exception_msg():
    return (
        'Is your Android VM/emulator running? MobSF cannot'
        ' find the android device identifier.'
        ' Please read official documentation.'
        ' If this error persists, set ANALYZER_IDENTIFIER in '
        'dexray.yaml or via environment variable'
        ' MOBSF_ANALYZER_IDENTIFIER')


def get_android_src_dir(app_dir, typ):
    """Get Android source code location."""
    if typ == 'apk':
        src = app_dir / 'java_source'
    elif typ == 'studio':
        src = app_dir / 'app' / 'src' / 'main' / 'java'
        kt = app_dir / 'app' / 'src' / 'main' / 'kotlin'
        if not src.exists() and kt.exists():
            src = kt
    elif typ == 'eclipse':
        src = app_dir / 'src'
    return src




def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    """Generate random string."""
    return ''.join(random.choice(chars) for _ in range(size))


def valid_host(host):
    """Check if host is valid."""
    try:
        prefixs = ('http://', 'https://')
        if not host.startswith(prefixs):
            host = f'http://{host}'
        parsed = urlparse(host)
        domain = parsed.netloc
        path = parsed.path
        if len(domain) == 0:
            # No valid domain
            return False
        if len(path) > 0:
            # Only host is allowed
            return False
        if ':' in domain:
            # IPv6
            return False
        # Local network
        invalid_prefix = (
            '100.64.',
            '127.',
            '192.',
            '198.',
            '10.',
            '172.',
            '169.',
            '0.',
            '203.0.',
            '224.0.',
            '240.0',
            '255.255.',
            'localhost',
            '::1',
            '64::ff9b::',
            '100::',
            '2001::',
            '2002::',
            'fc00::',
            'fe80::',
            'ff00::')
        if domain.startswith(invalid_prefix):
            return False
        ip = socket.gethostbyname(domain)
        if ip.startswith(invalid_prefix):
            # Resolve dns to get IP
            return False
        return True
    except Exception:
        return False
