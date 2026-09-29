import os,tempfile,json,base64,hashlib,hmac,struct,time,tarfile,io
from pathlib import Path
os.environ['SYPANEL_DATA']=tempfile.mkdtemp(prefix='sypanel-test-')
os.environ['SYPANEL_MODE']='sandbox'
import pytest
from werkzeug.security import generate_password_hash
from sypanel.app import app,totp_counter
from sypanel.core import db,DATA,agent,validate
from sypanel.worker import process_one
from sypanel.agent import Engine
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
TEST_KEY=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH).decode()

@pytest.fixture(autouse=True)
def reset():
    import shutil
    with db() as c:
        for table in ['sessions','users','resources','jobs','audit','attempts']: c.execute('DELETE FROM '+table)
        for name,role in [('admin','admin'),('viewer','viewer')]: c.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(name,generate_password_hash('CorrectPass_123!'),role))
    shutil.rmtree(DATA/'sandbox',ignore_errors=True)
@pytest.fixture
def client(): return app.test_client()
def login(c,user='admin'):
    token=c.get('/api/me').json['csrf']
    r=c.post('/api/login',json={'username':user,'password':'CorrectPass_123!'},headers={'X-CSRF-Token':token})
    assert r.status_code==200,r.json
    return {'X-CSRF-Token':r.json['csrf']}
def create(c,h,kind,data):
    r=c.post('/api/resources/'+kind,json=data,headers=h); assert r.status_code==202,r.json
    assert process_one()
    with db() as con: job=dict(con.execute('SELECT * FROM jobs WHERE id=?',(r.json['job'],)).fetchone())
    assert job['status']=='done',job['message']
    return r.json['id']
def site(c,h): return create(c,h,'sites',{'domain':'example.test','php':'static'})

def test_auth_csrf_logout(client):
    assert client.get('/api/resources/sites').status_code==401
    assert client.post('/api/login',json={}).status_code==403
    h=login(client); assert client.get('/api/overview').status_code==200
    assert client.post('/api/logout',json={},headers=h).status_code==200
    assert client.get('/api/overview').status_code==401

def test_login_rate_limit(client):
    h={'X-CSRF-Token':client.get('/api/me').json['csrf']}
    for _ in range(5): assert client.post('/api/login',json={'username':'admin','password':'wrong'},headers=h).status_code==401
    assert client.post('/api/login',json={'username':'admin','password':'wrong'},headers=h).status_code==429

def test_viewer_denied(client):
    h=login(client,'viewer'); assert client.get('/api/overview').status_code==200
    for path in ['/resources/sites','/service','/ssl','/users','/file']: assert client.post('/api'+path,json={},headers=h).status_code==403
    for path in ['/users','/audit','/files','/logs']: assert client.get('/api'+path).status_code==403

def test_site_file_crud_and_escape(client):
    h=login(client); site(client,h)
    def file(op,path,content=''): return client.post('/api/file',json={'domain':'example.test','op':op,'path':path,'content':base64.b64encode(content.encode()).decode()},headers=h)
    assert file('mkdir','app').status_code==200
    assert file('write','app/hello.txt','halo').status_code==200
    r=client.get('/api/file?domain=example.test&path=app/hello.txt');assert base64.b64decode(r.json['content'])==b'halo'
    assert file('write','../../evil','x').status_code==400
    assert file('write','/etc/passwd','x').status_code==400
    web=DATA/'sandbox/sites/example.test/public_html';(web/'escape').symlink_to('/tmp',target_is_directory=True)
    assert file('write','escape/evil','x').status_code!=200
    assert file('delete','app/hello.txt').status_code==200
    assert file('delete','app').status_code==200
    assert file('delete','.').status_code==400

def test_backup_restore_and_export(client):
    h=login(client); site(client,h)
    write=lambda text:client.post('/api/file',json={'domain':'example.test','op':'write','path':'note.txt','content':base64.b64encode(text.encode()).decode()},headers=h)
    write('original');bid=create(client,h,'backups',{'domain':'example.test'});write('changed')
    row=client.get('/api/resources/backups').json[0]
    r=client.post('/api/restore/'+str(bid),json={'confirm':row['name']},headers=h);assert r.status_code==202;process_one()
    assert base64.b64decode(client.get('/api/file?domain=example.test&path=note.txt').json['content'])==b'original'
    download=client.get('/api/download/backups/'+str(bid));assert download.status_code==200
    with tarfile.open(fileobj=io.BytesIO(download.data)) as t: assert 'public_html/note.txt' in t.getnames()

def test_jobs_and_secrets(client):
    h=login(client); site(client,h);pw="LongPass'word$123"
    create(client,h,'databases',{'domain':'example.test','name':'portal','password':pw})
    for route in ['/api/jobs','/api/resources/databases','/api/audit']: assert pw not in client.get(route).text
    with db() as c:
        for row in c.execute('SELECT payload FROM jobs'): assert row['payload']==''
    data=client.get('/api/resources/databases').json[0];assert client.get('/api/download/databases/'+str(data['id'])).status_code==200

def test_dns_cron_keys_redirects_mail(client):
    h=login(client); site(client,h)
    for kind,data in [('dns',{'host':'ns1','type':'A','value':'203.0.113.10'}),('dns',{'host':'@','type':'MX','value':'mail.example.test','priority':10}),('mailboxes',{'local':'admin','password':'MailboxPass_123'}),('forwarders',{'local':'info','target':'admin@elsewhere.test'}),('redirects',{'target':'https://elsewhere.test/'}),('sshkeys',{'label':'laptop','key':TEST_KEY})]: create(client,h,kind,dict(domain='example.test',**data))
    client.post('/api/file',json={'domain':'example.test','op':'write','path':'cron.php','content':base64.b64encode(b'<?php echo 1;').decode()},headers=h)
    create(client,h,'cron',{'domain':'example.test','script':'cron.php','schedule':'*/5 * * * *'})
    assert 'IN MX 10 mail.example.test.' in (DATA/'sandbox/config/etc/bind/sypanel/db.example.test').read_text()
    assert 'return 302 https://elsewhere.test/' in (DATA/'sandbox/config/etc/nginx/conf.d/sypanel-example.test.conf').read_text()

def test_delete_confirm_and_dependencies(client):
    h=login(client); sid=site(client,h)
    create(client,h,'databases',{'domain':'example.test','name':'portal','password':'StrongPass_123!'})
    assert client.delete('/api/resources/'+str(sid),json={'confirm':'wrong'},headers=h).status_code==400
    assert client.delete('/api/resources/'+str(sid),json={'confirm':'example.test'},headers=h).status_code==400
    row=client.get('/api/resources/databases').json[0]
    assert client.delete('/api/resources/'+str(row['id']),json={'confirm':row['name']},headers=h).status_code==202;process_one()
    assert client.get('/api/resources/databases').json==[]

@pytest.mark.parametrize('kind,data',[
 ('sites',{'domain':'test.com;rm -rf /'}),('sites',{'domain':'test.com','php':'8.3;id'}),
 ('dns',{'domain':'test.com','host':'@','type':'A','value':'127.0.0.1\ninclude /etc/passwd'}),
 ('dns',{'domain':'test.com','host':'@','type':'A','value':'::1'}),('dns',{'domain':'test.com','host':'@','type':'TXT','value':'x\ny'}),
 ('cron',{'domain':'test.com','script':'../evil.php','schedule':'* * * * *'}),
 ('cron',{'domain':'test.com','script':'a.php','schedule':'99 * * * *'}),
 ('cron',{'domain':'test.com','script':'a.php','schedule':'* * * * *\nroot id'}),
 ('redirects',{'domain':'test.com','target':'https://bad.test/;return 200;'}),
 ('databases',{'domain':'test.com','name':'x`;DROP DATABASE mysql','password':'LongSecret123'}),
 ('mailboxes',{'domain':'test.com','local':'admin\nx','password':'LongSecret123'})])
def test_validation(kind,data):
    with pytest.raises(ValueError): validate(kind,data)

def test_root_allowlist_and_missing_site():
    engine=Engine(DATA/'sandbox',live=False)
    for action,data in [('service',{'service':'nginx;id','op':'restart'}),('exec',{'command':'id'}),('file',{'domain':'notfound.test','op':'list'})]:
        with pytest.raises(ValueError): engine.dispatch(action,data)

def test_totp_and_replay(client):
    h=login(client);secret=client.post('/api/mfa/setup',json={},headers=h).json['secret']
    counter=int(time.time()//30);digest=hmac.new(base64.b32decode(secret),struct.pack('>Q',counter),hashlib.sha1).digest();o=digest[-1]&15
    code=str((struct.unpack('>I',digest[o:o+4])[0]&0x7fffffff)%1000000).zfill(6)
    assert totp_counter(secret,code)==counter
    assert client.post('/api/mfa/confirm',json={'password':'CorrectPass_123!','code':code},headers=h).status_code==200
    client.post('/api/logout',json={},headers=h);h={'X-CSRF-Token':client.get('/api/me').json['csrf']}
    assert client.post('/api/login',json={'username':'admin','password':'CorrectPass_123!','code':code},headers=h).status_code==401

def test_revoke_other_sessions(client):
    h=login(client);other=app.test_client();login(other)
    assert client.post('/api/password',json={'current':'CorrectPass_123!','password':'NewCorrectPass123!'},headers=h).status_code==200
    assert client.get('/api/overview').status_code==200;assert other.get('/api/overview').status_code==401

def test_failure_never_claims_active(client):
    h=login(client); site(client,h)
    r=client.post('/api/resources/cron',json={'domain':'example.test','script':'missing.php','schedule':'* * * * *'},headers=h)
    assert r.status_code==202;process_one()
    assert client.get('/api/resources/cron').json[0]['status']=='error'
    assert client.get('/api/jobs').json[0]['status']=='failed'

def test_update_resources(client):
    h=login(client); sid=site(client,h)
    dns_id=create(client,h,'dns',{'domain':'example.test','type':'A','host':'ns1','value':'203.0.113.10'})
    def update(rid,data):
        r=client.patch('/api/resources/'+str(rid),json=data,headers=h);assert r.status_code==202,r.json
        process_one();assert client.get('/api/jobs').json[0]['status']=='done',client.get('/api/jobs').json[0]
    update(dns_id,{'value':'203.0.113.11'})
    assert client.get('/api/resources/dns').json[0]['data']['value']=='203.0.113.11'
    update(sid,{'php':'8.3'})
    assert client.get('/api/resources/sites').json[0]['data']['php']=='8.3'
    did=create(client,h,'databases',{'domain':'example.test','name':'portal','password':'Password_123!'})
    update(did,{'password':'NewPassword_123!'})
    assert 'NewPassword_123!' not in client.get('/api/resources/databases').text
    assert client.patch('/api/resources/'+str(sid),json={'domain':'different.test'},headers=h).status_code==400
