import os,tempfile,json,base64,hashlib,hmac,struct,time,tarfile,io,re,subprocess
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
def site(c,h,php='static'): return create(c,h,'sites',{'domain':'example.test','php':php})
def job(c): return c.get('/api/jobs').json[0]
def put(c,h,path,content): return c.post('/api/file',json={'domain':'example.test','op':'write','path':path,'content':base64.b64encode(content).decode()},headers=h)
WEB=lambda:DATA/'sandbox/sites/example.test/public_html'
CONF=lambda name:DATA/'sandbox/config'/name.lstrip('/')

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
    h=login(client); site(client,h,'8.3')
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
    h=login(client); site(client,h,'8.3')
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

# Regression tests for the code review findings, most severe first.
def tarball(path,files):
    with tarfile.open(path,'w:gz') as t:
        for name,data in files:
            info=tarfile.TarInfo(name); info.size=len(data); t.addfile(info,io.BytesIO(data))

def test_site_update_never_writes_through_index_symlink(client):
    h=login(client); sid=site(client,h); target=DATA/'escaped.txt'
    (WEB()/'index.html').unlink(); (WEB()/'index.html').symlink_to(target)
    assert client.patch('/api/resources/'+str(sid),json={'php':'8.3'},headers=h).status_code==202; process_one()
    assert job(client)['status']=='done' and not target.exists() and (WEB()/'index.html').is_symlink()

def test_backup_and_restore_run_as_site_user(monkeypatch):
    engine=Engine(DATA/'sandbox',live=False); name='example.test-0123456789ab'
    engine.state['sites:example.test']={'domain':'example.test','name':'example.test','php':'static'}
    engine.state['backups:'+name]={'domain':'example.test','name':name,'filename':name+'.tar.gz'}
    WEB().mkdir(parents=True); tarball(engine.backups/(name+'.tar.gz'),[('public_html/a.txt',b'a')])
    calls=[]
    def fake(args,**kw): calls.append(args); return subprocess.CompletedProcess(args,0,stderr=b'')
    monkeypatch.setattr('sypanel.agent.subprocess.run',fake); engine.live=True
    engine.backup({'domain':'example.test','name':'example.test-aaaaaaaaaaaa'}); engine.restore({'name':name})
    assert [x[:4] for x in calls]==[['runuser','-u',engine.uid('example.test'),'--']]*2 and [x[-1] for x in calls]==['archive','extract']

def test_unknown_fields_are_dropped(client):
    assert set(validate('sites',{'domain':'x.test','php':'static','ssl':True,'junk':'y'}))=={'domain','name','php'}
    h=login(client); create(client,h,'sites',{'domain':'example.test','php':'static','ssl':True,'junk':'x'*1000})
    state=json.loads((DATA/'sandbox/state.json').read_text())['sites:example.test']
    for data in (client.get('/api/resources/sites').json[0]['data'],state): assert 'junk' not in data and data.get('ssl') is not True
    assert 'listen 443' not in CONF('/etc/nginx/conf.d/sypanel-example.test.conf').read_text()

def test_delete_after_failed_create_unblocks_site(client):
    h=login(client); sid=site(client,h,'8.3')
    client.post('/api/resources/cron',json={'domain':'example.test','script':'missing.php','schedule':'* * * * *'},headers=h); process_one()
    row=client.get('/api/resources/cron').json[0]; assert row['status']=='error'
    assert client.delete('/api/resources/'+str(row['id']),json={'confirm':row['name']},headers=h).status_code==202; process_one()
    assert job(client)['status']=='done' and client.get('/api/resources/cron').json==[]
    assert client.delete('/api/resources/'+str(sid),json={'confirm':'example.test'},headers=h).status_code==202; process_one()
    assert job(client)['status']=='done' and client.get('/api/resources/sites').json==[]

def test_discard_clears_leftovers_of_unrecorded_site():
    engine=Engine(DATA/'sandbox',live=False); pool=CONF('/etc/php/8.3/fpm/pool.d/'+engine.uid('example.test')+'.conf')
    pool.parent.mkdir(parents=True); pool.write_text('[leftover]')
    assert 'tidak tercatat' in engine.dispatch('sites.delete',{'domain':'example.test','name':'example.test','php':'8.3'})['message'] and not pool.exists()
    with pytest.raises(ValueError): engine.dispatch('sites.delete',{'domain':'x.test','name':'x.test','php':'../../../etc'})

def test_queued_rename_reserves_name(client):
    h=login(client); site(client,h)
    rid=create(client,h,'dns',{'domain':'example.test','type':'A','host':'ns1','value':'203.0.113.10'})
    assert client.patch('/api/resources/'+str(rid),json={'value':'203.0.113.11'},headers=h).status_code==202
    assert client.post('/api/resources/dns',json={'domain':'example.test','type':'A','host':'ns1','value':'203.0.113.11'},headers=h).status_code==400
    process_one(); assert job(client)['status']=='done'
    # A conflict that slips past the API must not leave a job that replays an applied change.
    assert client.patch('/api/resources/'+str(rid),json={'value':'203.0.113.12'},headers=h).status_code==202
    with db() as c: c.execute("INSERT INTO resources(kind,name,data) VALUES('dns','example.test:ns1:A:203.0.113.12','{}')")
    process_one(); failed=job(client)
    assert failed['status']=='failed' and 'sudah diterapkan' in failed['message']
    with db() as c: assert c.execute('SELECT payload FROM jobs WHERE id=?',(failed['id'],)).fetchone()['payload']==''
    assert client.post('/api/jobs/'+str(failed['id'])+'/retry',json={},headers=h).status_code==400

def test_restore_checks_archive_before_writing(client):
    h=login(client); site(client,h); put(client,h,'a.txt',b'original'); big=b'x'*(17*1024**2); (WEB()/'big.bin').write_bytes(big)
    bid=create(client,h,'backups',{'domain':'example.test'}); row=client.get('/api/resources/backups').json[0]
    put(client,h,'a.txt',b'changed'); (WEB()/'big.bin').write_bytes(b'')
    restore=lambda:client.post('/api/restore/'+str(bid),json={'confirm':row['name']},headers=h).status_code==202 and process_one()
    assert restore() and job(client)['status']=='done'
    assert (WEB()/'a.txt').read_bytes()==b'original' and (WEB()/'big.bin').read_bytes()==big
    put(client,h,'a.txt',b'changed'); tarball(DATA/'sandbox/backups'/row['data']['filename'],[('public_html/a.txt',b'evil'),('../escape.txt',b'x')])
    assert restore() and job(client)['status']=='failed' and (WEB()/'a.txt').read_bytes()==b'changed'

def test_login_lockout_is_per_client(client):
    token=client.get('/api/me').json['csrf']
    def attempt(ip,password): return client.post('/api/login',json={'username':'admin','password':password},headers={'X-CSRF-Token':token},environ_base={'REMOTE_ADDR':ip}).status_code
    for _ in range(5): assert attempt('2001:db8::1','wrong')==401
    assert attempt('2001:db8::2','CorrectPass_123!')==429
    assert attempt('203.0.113.9','CorrectPass_123!')==200

def test_redirect_covers_php_urls(client):
    h=login(client); site(client,h,'8.3'); create(client,h,'redirects',{'domain':'example.test','target':'https://elsewhere.test/'})
    conf=CONF('/etc/nginx/conf.d/sypanel-example.test.conf').read_text()
    assert 'return 302 https://elsewhere.test/' in conf and 'fastcgi_pass' not in conf

def test_retry_refuses_stale_job(client):
    h=login(client); site(client,h,'8.3'); put(client,h,'a.php',b'<?php'); put(client,h,'b.php',b'<?php')
    rid=create(client,h,'cron',{'domain':'example.test','script':'a.php','schedule':'* * * * *'})
    client.patch('/api/resources/'+str(rid),json={'script':'missing.php'},headers=h); process_one(); stale=job(client); assert stale['status']=='failed'
    client.patch('/api/resources/'+str(rid),json={'script':'b.php'},headers=h); process_one(); assert job(client)['status']=='done'
    assert client.post('/api/jobs/'+str(stale['id'])+'/retry',json={},headers=h).status_code==400
    r=client.post('/api/resources/cron',json={'domain':'example.test','script':'missing.php','schedule':'* * * * *'},headers=h); process_one()
    assert client.post('/api/jobs/'+str(r.json['job'])+'/retry',json={},headers=h).status_code==200

def test_cron_schedule_is_normalized():
    assert validate('cron',{'domain':'test.com','script':'a.php','schedule':'*\n* * *\t*'})['schedule']=='* * * * *'

def test_long_txt_is_split_for_bind(client):
    h=login(client); site(client,h); value='v=DKIM1; k=rsa; p='+'A'*380+'"q\\'
    create(client,h,'dns',{'domain':'example.test','host':'mail._domainkey','type':'TXT','value':value})
    line=[x for x in CONF('/etc/bind/sypanel/db.example.test').read_text().splitlines() if '_domainkey' in x][0]
    parts=[re.sub(r'\\(.)',r'\1',x) for x in re.findall(r'"((?:[^"\\]|\\.)*)"',line)]
    assert len(parts)==2 and all(len(x.encode())<=255 for x in parts) and ''.join(parts)==value

def test_db_export_keeps_binary_bytes(monkeypatch):
    engine=Engine(DATA/'sandbox',live=False); engine.state['databases:sy_portal']={'domain':'example.test','name':'sy_portal'}; engine.live=True
    calls=[]
    def fake(args,data=None,timeout=90,text=True): calls.append((args,text)); return b'INSERT \xff\x00;'
    monkeypatch.setattr('sypanel.agent.run',fake)
    assert base64.b64decode(engine.dispatch('db_export',{'name':'sy_portal'})['content'])==b'INSERT \xff\x00;'
    assert '--hex-blob' in calls[0][0] and calls[0][1] is False

def test_cron_follows_site_php(client):
    h=login(client); sid=site(client,h,'8.1'); put(client,h,'job.php',b'<?php')
    create(client,h,'cron',{'domain':'example.test','script':'job.php','schedule':'* * * * *'})
    cron=lambda:CONF('/etc/cron.d/sypanel-sy'+hashlib.sha256(b'example.test').hexdigest()[:12]).read_text()
    assert '/usr/bin/php8.1 ' in cron()
    client.patch('/api/resources/'+str(sid),json={'php':'8.3'},headers=h); process_one()
    assert job(client)['status']=='done' and '/usr/bin/php8.3 ' in cron()
    assert client.patch('/api/resources/'+str(sid),json={'php':'static'},headers=h).status_code==400
    create(client,h,'sites',{'domain':'static.test','php':'static'})
    assert client.post('/api/resources/cron',json={'domain':'static.test','script':'job.php','schedule':'* * * * *'},headers=h).status_code==400
    with pytest.raises(ValueError,match='situs PHP'): Engine(DATA/'sandbox',live=False).dispatch('cron.create',{'domain':'static.test','script':'job.php','schedule':'* * * * *'})

def test_metrics_reads_all_units_in_one_call(monkeypatch):
    engine=Engine(DATA/'sandbox',live=False); engine.live=True; calls=[]
    def fake(args,**kw): calls.append(args); return subprocess.CompletedProcess(args,3,stdout='active\ninactive\nactive\nfailed\nactive\ninactive\nactive\n')
    monkeypatch.setattr('sypanel.agent.subprocess.run',fake)
    services=engine.dispatch('metrics',{})['services']
    assert len(calls)==1 and services=={'nginx':'active','mariadb':'inactive','ssh':'active','cron':'inactive','bind9':'active','postfix':'inactive','dovecot':'active'}
