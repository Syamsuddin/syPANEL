import os, json, sqlite3, secrets, re, ipaddress, socket
from pathlib import Path
from cryptography.fernet import Fernet

DATA = Path(os.environ.get('SYPANEL_DATA', './var')).resolve()
DATA.mkdir(parents=True, exist_ok=True)
MODE = os.environ.get('SYPANEL_MODE', 'sandbox')
SOCKET = os.environ.get('SYPANEL_SOCKET', '/run/sypanel/agent.sock')

def secret(name, factory):
    path = DATA / name
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f: f.write(factory())
    except FileExistsError: pass
    return path.read_text().strip()

KEY = secret('encryption.key', lambda: Fernet.generate_key().decode())
SESSION_KEY = secret('session.key', lambda: secrets.token_hex(48))
CIPHER = Fernet(KEY.encode())

from contextlib import contextmanager

@contextmanager
def db():
    c = sqlite3.connect(DATA / 'panel.sqlite3', timeout=30)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    try:
        with c:
            yield c
    finally:
        c.close()

def init():
    with db() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL, role TEXT NOT NULL, totp TEXT, pending_totp TEXT,
          last_totp INTEGER DEFAULT -1, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS resources(id INTEGER PRIMARY KEY, kind TEXT NOT NULL,
          name TEXT NOT NULL, data TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          created TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(kind,name));
        CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, action TEXT NOT NULL,
          payload TEXT NOT NULL, resource_id INTEGER, status TEXT DEFAULT 'queued',
          message TEXT DEFAULT '', created TEXT DEFAULT CURRENT_TIMESTAMP, finished TEXT);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT, action TEXT,
          detail TEXT, ip TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS attempts(ip TEXT PRIMARY KEY, count INTEGER, until REAL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER,
          expires REAL NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        ''')

def encrypt(data): return CIPHER.encrypt(json.dumps(data).encode()).decode()
def decrypt(value): return json.loads(CIPHER.decrypt(value.encode()))
def public(data): return {k:v for k,v in data.items() if k not in {'password','secret','token'}}
def domain(value):
    value = str(value).lower().rstrip('.')
    if len(value)>253 or not re.fullmatch(r'(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?',value):
        raise ValueError('Nama domain tidak valid, contoh: contoh.id')
    return value

def identifier(value):
    if not re.fullmatch(r'[a-z][a-z0-9_]{2,23}',str(value)): raise ValueError('Nama harus 3-24 karakter, huruf kecil, angka atau garis bawah.')
    return str(value)

def password(value):
    value = str(value)
    if len(value)<12 or len(value)>128 or any(ord(x)<32 for x in value): raise ValueError('Password wajib 12-128 karakter tanpa karakter kontrol.')
    return value

def path_relative(value):
    value = str(value)
    p = Path(value)
    if '\x00' in value or '\\' in value or p.is_absolute() or '..' in p.parts or len(value)>512:
        raise ValueError('Path wajib relatif dan tidak boleh keluar dari direktori situs.')
    return value or '.'

KINDS = {'sites','databases','dns','mailboxes','forwarders','cron','sshkeys','redirects','backups'}
def validate(kind, raw):
    d = dict(raw)
    if kind not in KINDS: raise ValueError('Modul tidak dikenal.')
    d['domain'] = domain(d.get('domain',''))
    if kind == 'sites':
        d['php'] = str(d.get('php','8.3'))
        if d['php'] not in ('8.1','8.3','static'): raise ValueError('Pilih PHP 8.1, 8.3, atau static.')
        d['name'] = d['domain']
    elif kind == 'databases':
        d['name'] = 'sy_' + identifier(str(d.get('name','')).removeprefix('sy_'))
        d['password'] = password(d.get('password',''))
    elif kind == 'dns':
        d['type'] = str(d.get('type','A')).upper()
        if d['type'] not in ['A','AAAA','CNAME','MX','TXT','CAA']: raise ValueError('Jenis DNS tidak didukung.')
        d['host'] = str(d.get('host','@')).lower()
        if d['host'] != '@' and not re.fullmatch(r'(\*|[a-z0-9_](?:[a-z0-9_.-]{0,100}))',d['host']): raise ValueError('Host DNS tidak valid.')
        d['value'] = str(d.get('value','')).strip()
        if not d['value'] or len(d['value'])>1000 or any(ord(x)<32 for x in d['value']): raise ValueError('Isi DNS tidak valid.')
        if d['type'] in ('A','AAAA'):
            address = ipaddress.ip_address(d['value'])
            if address.version != (4 if d['type']=='A' else 6): raise ValueError('Versi alamat IP tidak sesuai.')
        if d['type'] in ('CNAME','MX'): d['value'] = domain(d['value'])+'.'
        if d['type']=='CAA' and not re.fullmatch(r'0 (issue|issuewild|iodef) "[a-zA-Z0-9.:/@_-]+"',d['value']): raise ValueError('Contoh CAA: 0 issue "letsencrypt.org"')
        d['ttl'] = int(d.get('ttl',3600)); d['priority'] = int(d.get('priority',10))
        if not 60<=d['ttl']<=604800 or not 0<=d['priority']<=65535: raise ValueError('TTL/prioritas di luar batas.')
        d['name'] = f"{d['domain']}:{d['host']}:{d['type']}:{d['value']}"
    elif kind in ('mailboxes','forwarders'):
        d['local'] = str(d.get('local','')).lower()
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}',d['local']): raise ValueError('Nama kotak email tidak valid.')
        d['name'] = d['local']+'@'+d['domain']
        if kind=='mailboxes': d['password'] = password(d.get('password',''))
        else:
            target = str(d.get('target',''))
            if not re.fullmatch(r'[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+',target): raise ValueError('Email tujuan tidak valid.')
            local,host=target.rsplit('@',1); d['target']=local+'@'+domain(host)
            if d['target']==d['name']: raise ValueError('Penerusan tidak boleh ke alamat yang sama.')
    elif kind=='cron':
        d['script'] = path_relative(d.get('script',''))
        if not d['script'].endswith('.php') or not re.fullmatch(r'[a-zA-Z0-9_./-]+',d['script']): raise ValueError('Cron menjalankan file .php di dalam situs.')
        d['schedule'] = str(d.get('schedule','')).strip()
        fields=d['schedule'].split(); bounds=[(0,59),(0,23),(1,31),(1,12),(0,7)]
        if len(fields)!=5: raise ValueError('Jadwal cron memerlukan 5 kolom.')
        for value,(lo,hi) in zip(fields,bounds):
            for part in value.split(','):
                if not re.fullmatch(r'(\*|\d+(?:-\d+)?)(?:/\d+)?',part): raise ValueError('Format cron tidak valid.')
                term,*step=part.split('/')
                if step and not 1<=int(step[0])<=hi+1: raise ValueError('Interval cron tidak valid.')
                if term!='*':
                    nums=list(map(int,term.split('-')))
                    if any(n<lo or n>hi for n in nums) or nums[0]>nums[-1]: raise ValueError('Rentang cron tidak valid.')
        d['name']=d['domain']+':'+d['script']
    elif kind=='sshkeys':
        d['label']=identifier(d.get('label','key'))
        d['key']=str(d.get('key','')).strip()
        if not re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]{40,2000}(?: [a-zA-Z0-9@._ -]{1,100})?',d['key']): raise ValueError('Public key SSH tidak valid.')
        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        try: load_ssh_public_key(d['key'].encode())
        except Exception: raise ValueError('Isi public key SSH tidak dapat dibaca.')
        d['name']=d['domain']+':'+d['label']
    elif kind=='redirects':
        from urllib.parse import urlsplit
        d['target']=str(d.get('target',''))
        u=urlsplit(d['target'])
        if u.scheme not in ('https','http') or not u.hostname or u.username or re.search(r'[\s;{}$"\\]',d['target']): raise ValueError('URL redirect tidak valid.')
        domain(u.hostname)
        if u.hostname==d['domain']: raise ValueError('Redirect ke domain yang sama ditolak.')
        d['name']=d['domain']
    elif kind=='backups':
        d['name']=str(d.get('name') or d['domain']+'-'+secrets.token_hex(6))
        if not re.fullmatch(re.escape(d['domain'])+r'-[a-f0-9]{12}',d['name']): raise ValueError('Nama cadangan tidak valid.')
    return d

def agent(action, payload=None):
    if MODE=='sandbox':
        from .agent import Engine
        return Engine(DATA/'sandbox', live=False).dispatch(action,payload or {})
    request=json.dumps({'action':action,'data':payload or {}}).encode()+b'\n'
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(240); s.connect(SOCKET); s.sendall(request); s.shutdown(socket.SHUT_WR)
        chunks=[]; size=0
        while True:
            chunk=s.recv(65536)
            if not chunk: break
            size+=len(chunk)
            if size>90*1024*1024: raise ValueError('Respons terlalu besar.')
            chunks.append(chunk)
    result=json.loads(b''.join(chunks))
    if not result['ok']: raise ValueError(result.get('error','Agent gagal.'))
    return result['result']
