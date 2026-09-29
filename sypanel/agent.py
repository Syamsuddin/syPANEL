"""Privileged narrow-operation agent. Unix socket; Linux peer UID authentication."""
import os, json, subprocess, hashlib, socket, struct, pwd, grp, time, re, base64, tarfile, io, shutil, platform
from pathlib import Path
from .core import validate, domain, public, path_relative

SERVICES={'nginx','mariadb','bind9','named','ssh','cron','php8.1-fpm','php8.3-fpm','postfix','dovecot'}

def run(args, data=None, timeout=90):
    p=subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    if p.returncode: raise ValueError((p.stderr or p.stdout or 'Layanan mengembalikan kesalahan.')[-1800:])
    return p.stdout

def atomic(path, content, mode=0o640):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.sypanel-tmp')
    # Managed configuration directories are root-owned, never writable by hosted users.
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'w') as f: f.write(content)
    os.chmod(tmp,mode); os.replace(tmp,path)

class Engine:
    def __init__(self, root=None, live=True):
        self.live=live
        self.base=Path(root or '/var/lib/sypanel-agent').resolve()
        self.base.mkdir(parents=True,exist_ok=True)
        self.sites=Path('/srv/sypanel/sites') if live else self.base/'sites'
        self.backups=Path('/var/backups/sypanel') if live else self.base/'backups'
        self.backups.mkdir(parents=True,exist_ok=True)
        self.statefile=self.base/'state.json'
        self.state=json.loads(self.statefile.read_text()) if self.statefile.exists() else {}
    def save(self): atomic(self.statefile,json.dumps(self.state),0o600)
    def uid(self,d): return 'sy'+hashlib.sha256(d.encode()).hexdigest()[:12]
    def site(self,d):
        d=domain(d)
        if 'sites:'+d not in self.state: raise ValueError('Situs belum aktif pada agent.')
        return self.sites/d/'public_html'
    def config(self,path): return Path(path) if self.live else self.base/'config'/path.lstrip('/')
    def apply_config(self,path,text,test,reload):
        path=self.config(path); old=path.read_text() if path.exists() else None
        atomic(path,text,0o644 if str(path).endswith('/zones.conf') else 0o640)
        if self.live:
            try: run(test); run(reload)
            except Exception:
                if old is None: path.unlink(missing_ok=True)
                else: atomic(path,old,0o644 if str(path).endswith('/zones.conf') else 0o640)
                # Reload only validated old configuration.
                try: run(test); run(reload)
                except Exception: pass
                raise
    def web_config(self,d):
        name=domain(d['domain']); root=self.sites/name/'public_html'; php=d.get('php','8.3')
        secure=d.get('ssl',False)
        lines=f'server {{\n listen 80;\n server_name {name};\n root {root};\n index index.php index.html;\n client_max_body_size 16m;\n access_log /var/log/nginx/sypanel-{name}.access.log;\n error_log /var/log/nginx/sypanel-{name}.error.log;\n location ^~ /.well-known/acme-challenge/ {{ allow all; }}\n'
        if secure: lines+=f' location / {{ return 301 https://{name}$request_uri; }}\n}}\nserver {{\n listen 443 ssl;\n server_name {name};\n root {root};\n index index.php index.html;\n ssl_certificate /etc/letsencrypt/live/{name}/fullchain.pem;\n ssl_certificate_key /etc/letsencrypt/live/{name}/privkey.pem;\n ssl_protocols TLSv1.2 TLSv1.3;\n client_max_body_size 16m;\n access_log /var/log/nginx/sypanel-{name}.access.log;\n error_log /var/log/nginx/sypanel-{name}.error.log;\n'
        redirect=self.state.get('redirects:'+name)
        if redirect: lines+=f" location / {{ return 302 {redirect['target']}; }}\n"
        else: lines+=' location / { try_files $uri $uri/ /index.php?$query_string; }\n'
        if php!='static': lines+=f' location ~ \\.php$ {{ try_files $uri =404; include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass unix:/run/php/{self.uid(name)}.sock; }}\n'
        else: lines+=' location ~ \\.php$ { deny all; }\n'
        lines+=' location ~ /\\. { deny all; }\n}\n'
        return lines
    def web_apply(self,d):
        self.apply_config('/etc/nginx/conf.d/sypanel-'+d['domain']+'.conf',self.web_config(d),['nginx','-t'],['systemctl','reload','nginx'])
    def create_site(self,d):
        user=self.uid(d['domain']); root=self.sites/d['domain']; web=root/'public_html'
        root.mkdir(parents=True,exist_ok=True); web.mkdir(exist_ok=True)
        if self.live: os.chown(root,0,0); os.chmod(root,0o755)
        if self.live:
            if d['php']!='static' and not Path('/usr/sbin/php-fpm'+d['php']).exists(): raise ValueError('Versi PHP belum terpasang. Pilih versi PHP bawaan Ubuntu.')
            try: pwd.getpwnam(user)
            except KeyError: run(['useradd','--user-group','--no-create-home','--home-dir',str(root),'--shell','/usr/sbin/nologin','--groups','sypanel-sites',user])
            run(['usermod','--password','*',user])
            info=pwd.getpwnam(user); os.chown(web,info.pw_uid,info.pw_gid); os.chmod(web,0o750)
            # Nginx needs traversal/read, hosted users remain mutually separated.
            run(['setfacl','-m','u:www-data:rx',str(web)])
            run(['setfacl','-d','-m','u:www-data:rx',str(web)])
            ssh=f'Match User {user}\n ChrootDirectory {root}\n ForceCommand internal-sftp -d /public_html\n AuthorizedKeysFile /etc/ssh/sypanel/%u\n PasswordAuthentication no\n AllowTcpForwarding no\n X11Forwarding no\n PermitTunnel no\nMatch all\n'
            self.apply_config('/etc/ssh/sshd_config.d/sypanel-'+user+'.conf',ssh,['sshd','-t'],['systemctl','reload','ssh'])
        if not (web/'index.html').exists():
            (web/'index.html').write_text('<!doctype html><meta charset="utf-8"><title>'+d['domain']+'</title><h1>'+d['domain']+'</h1><p>Website aktif. Dikelola melalui syPanel.</p>')
            if self.live:
                os.chown(web/'index.html',info.pw_uid,info.pw_gid); os.chmod(web/'index.html',0o640)
        if d['php']!='static':
            pool=f'[{user}]\nuser = {user}\ngroup = {user}\nlisten = /run/php/{user}.sock\nlisten.owner = www-data\nlisten.group = www-data\npm = ondemand\npm.max_children = 5\npm.process_idle_timeout = 10s\nphp_admin_value[open_basedir] = {web}:/tmp\nphp_admin_value[upload_tmp_dir] = /tmp\nphp_admin_flag[log_errors] = on\nsecurity.limit_extensions = .php\n'
            self.apply_config('/etc/php/'+d['php']+'/fpm/pool.d/'+user+'.conf',pool,['php-fpm'+d['php'],'-t'],['systemctl','reload','php'+d['php']+'-fpm'])
        self.web_apply(d)
        return {'user':user,'root':str(web)}
    def dns_apply(self):
        zones=sorted({x['domain'] for k,x in self.state.items() if k.startswith('dns:')})
        include=''
        for name in zones:
            # NS address supplied through an A record for host ns1 in the zone.
            body=f'$ORIGIN {name}.\n$TTL 3600\n@ IN SOA ns1.{name}. hostmaster.{name}. ({int(time.time())} 3600 900 1209600 300)\n@ IN NS ns1.{name}.\n'
            for k,x in self.state.items():
                if not k.startswith('dns:') or x['domain']!=name: continue
                val=x['value']
                if x['type']=='TXT': val='"'+val.replace('\\','\\\\').replace('"','\\"')+'"'
                if x['type']=='MX': val=str(x['priority'])+' '+val
                body+=f"{x['host']} {x['ttl']} IN {x['type']} {val}\n"
            path=self.config('/etc/bind/sypanel/db.'+name); old=path.read_text() if path.exists() else None
            atomic(path,body,0o644)
            if self.live:
                try: run(['named-checkzone',name,str(path)])
                except Exception:
                    if old is None: path.unlink(missing_ok=True)
                    else: atomic(path,old,0o644)
                    raise
            include+=f'zone "{name}" {{ type master; file "/etc/bind/sypanel/db.{name}"; }};\n'
        self.apply_config('/etc/bind/sypanel/zones.conf',include,['named-checkconf'],['rndc','reload'])
    def mail_apply(self):
        if self.live and not Path('/etc/sypanel-mail.enabled').exists(): raise ValueError('Integrasi email belum dipasang. Jalankan deploy/mail.sh sesuai panduan.')
        boxes=[x for k,x in self.state.items() if k.startswith('mailboxes:')]
        forwards=[x for k,x in self.state.items() if k.startswith('forwarders:')]
        domains=sorted({x['domain'] for x in boxes+forwards})
        maps={'domains':'\n'.join(x+' OK' for x in domains)+'\n',
              'mailboxes':'\n'.join(x['name']+' '+x['domain']+'/'+x['local']+'/' for x in boxes)+'\n',
              'aliases':'\n'.join(x['name']+' '+x['target'] for x in forwards)+'\n'}
        for name,body in maps.items():
            p=self.config('/etc/postfix/sypanel/'+name); atomic(p,body,0o640)
            if self.live:
                gid=grp.getgrnam('postfix').gr_gid
                os.chown(p,0,gid)
                run(['postmap',str(p)])
                os.chown(str(p)+'.db',0,gid); os.chmod(str(p)+'.db',0o640)
        auth='\n'.join(x['name']+':'+x['hash']+':5000:5000::/var/vmail/'+x['domain']+'/'+x['local']+'::userdb_mail=maildir:~/Maildir' for x in boxes)+'\n'
        path=self.config('/etc/dovecot/sypanel-users'); atomic(path,auth,0o640)
        if self.live:
            os.chown(path,0,grp.getgrnam('dovecot').gr_gid)
            run(['postfix','check']); run(['systemctl','reload','postfix']); run(['systemctl','reload','dovecot'])
    def cron_apply(self,d):
        user=self.uid(d); jobs=[x for k,x in self.state.items() if k.startswith('cron:') and x['domain']==d]
        content='SHELL=/bin/sh\nPATH=/usr/bin:/bin\nMAILTO=""\n'
        for x in jobs: content+=f"{x['schedule']} {user} /usr/bin/php {self.sites/d/'public_html'/x['script']} >/dev/null 2>&1\n"
        atomic(self.config('/etc/cron.d/sypanel-'+user),content,0o644)
    def keys_apply(self,d):
        keys=[x['key'] for k,x in self.state.items() if k.startswith('sshkeys:') and x['domain']==d]
        atomic(self.config('/etc/ssh/sypanel/'+self.uid(d)),'\n'.join(keys)+'\n',0o644)
    def file(self,d):
        root=self.site(d['domain']); action=d['op']; data={k:v for k,v in d.items() if k not in ('domain','op')}
        if self.live:
            command=['runuser','-u',self.uid(d['domain']),'--','/opt/sypanel/.venv/bin/python','/opt/sypanel/sypanel/fileops.py',str(root)]
            try: out=run(command,json.dumps({'action':action,'data':data}))
            except ValueError: raise ValueError('Akses file gagal. Periksa path, izin, ukuran, atau folder yang belum kosong.')
            return json.loads(out)['result']
        from .fileops import operate
        return operate(root,action,data)
    def backup(self,d):
        root=self.site(d['domain']); archive=self.backups/(d['name']+'.tar.gz')
        # tar never follows symlinks; only regular files and directories are stored.
        def filt(info): return info if info.isfile() or info.isdir() else None
        with tarfile.open(archive,'w:gz',dereference=False) as t: t.add(root,arcname='public_html',filter=filt)
        os.chmod(archive,0o600)
        return {'filename':archive.name,'bytes':archive.stat().st_size}
    def restore(self,d):
        saved=self.state.get('backups:'+str(d.get('name','')))
        if not saved: raise ValueError('Cadangan tidak ditemukan.')
        root=self.site(saved['domain']); archive=self.backups/saved['filename']
        with tarfile.open(archive,'r:gz') as t:
            members=t.getmembers()
            if sum(x.size for x in members)>2*1024**3: raise ValueError('Cadangan melebihi 2 GiB.')
            for m in members:
                p=Path(m.name)
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='public_html' or not (m.isdir() or m.isfile()): raise ValueError('Isi arsip tidak aman.')
                # Restore via file helper as the isolated site account, never root extraction.
                relative=str(Path(*p.parts[1:]))
                if relative=='.': continue
                if m.isdir():
                    try: self.file({'domain':saved['domain'],'op':'mkdir','path':relative})
                    except Exception:
                        self.file({'domain':saved['domain'],'op':'list','path':relative})
                else:
                    if m.size>16*1024**2: raise ValueError('Restore panel dibatasi 16 MiB per file.')
                    self.file({'domain':saved['domain'],'op':'write','path':relative,'content':base64.b64encode(t.extractfile(m).read()).decode()})
        return {'message':'File dipulihkan. File tambahan tidak dihapus.'}
    def update(self,kind,data):
        if kind not in ('sites','databases','dns','mailboxes','forwarders','cron','sshkeys','redirects'): raise ValueError('Objek tidak dapat diubah.')
        old_key=kind+':'+str(data.get('_old_name',''))
        old_item=self.state.get(old_key)
        if not old_item: raise ValueError('Objek agent tidak ditemukan.')
        d=validate(kind,data)
        if d['domain']!=old_item['domain']: raise ValueError('Perpindahan domain tidak didukung.')
        if kind in ('databases','mailboxes') and d['name']!=old_item['name']: raise ValueError('Nama objek tidak boleh diubah.')
        key=kind+':'+d['name']
        if key!=old_key and key in self.state: raise ValueError('Objek dengan nama tersebut sudah ada.')
        before=dict(self.state)
        d.pop('_old_name',None)
        if kind=='sites': d['ssl']=old_item.get('ssl',False)
        del self.state[old_key]; self.state[key]=public(d)
        try:
            if kind=='sites':
                old_php=old_item.get('php','static')
                if old_php!=d['php'] and old_php!='static':
                    self.config('/etc/php/'+old_php+'/fpm/pool.d/'+self.uid(d['domain'])+'.conf').unlink(missing_ok=True)
                    if self.live: run(['systemctl','reload','php'+old_php+'-fpm'])
                self.state[key].update(self.create_site(d))
            elif kind=='databases':
                if self.live:
                    pw=d['password'].replace("'","''"); name=d['name']
                    try: run(['mariadb','--batch'],f"SET SESSION sql_mode='NO_BACKSLASH_ESCAPES'; ALTER USER '{name}'@'localhost' IDENTIFIED BY '{pw}';")
                    except ValueError: raise ValueError('Penggantian password database gagal.')
            elif kind=='dns': self.dns_apply()
            elif kind in ('mailboxes','forwarders'):
                if kind=='mailboxes':
                    self.state[key]['hash']='{SHA512-CRYPT}'+run(['openssl','passwd','-6','-stdin'],d['password']+'\n').strip() if self.live else '{SIMULATED}'
                self.mail_apply()
            elif kind=='cron':
                self.file({'domain':d['domain'],'op':'read','path':d['script']}); self.cron_apply(d['domain'])
            elif kind=='sshkeys': self.keys_apply(d['domain'])
            elif kind=='redirects': self.web_apply(self.state['sites:'+d['domain']])
            self.save()
            updated={k:v for k,v in self.state[key].items() if k not in ('password','hash','_old_name')}
            return {'updated':updated,'message':'Perubahan disimpan.' if self.live else 'Simulasi perubahan disimpan.'}
        except Exception:
            self.state=before
            try:
                if kind=='sites':
                    if d['php']!=old_item.get('php') and d['php']!='static':
                        self.config('/etc/php/'+d['php']+'/fpm/pool.d/'+self.uid(d['domain'])+'.conf').unlink(missing_ok=True)
                        if self.live: run(['systemctl','reload','php'+d['php']+'-fpm'])
                    self.create_site(old_item)
                elif kind=='dns': self.dns_apply()
                elif kind in ('mailboxes','forwarders'): self.mail_apply()
                elif kind=='redirects': self.web_apply(self.state['sites:'+d['domain']])
                elif kind=='cron': self.cron_apply(d['domain'])
                elif kind=='sshkeys': self.keys_apply(d['domain'])
            except Exception: pass
            raise
    def dispatch(self,action,data):
        if action=='metrics':
            import psutil
            disk=psutil.disk_usage(str(self.base)); mem=psutil.virtual_memory()
            states={s:(run(['systemctl','is-active',s]).strip() if self.is_active(s) else 'inactive') for s in ['nginx','mariadb','ssh','cron','bind9','postfix','dovecot']} if self.live else {s:'sandbox' for s in ['nginx','mariadb','ssh','cron','bind9','postfix','dovecot']}
            return {'hostname':socket.gethostname(),'os':platform.platform(),'cpu':psutil.cpu_percent(interval=.15),'memory':mem.percent,'memory_total':mem.total,'disk':disk.percent,'disk_used':disk.used,'disk_total':disk.total,'load':list(os.getloadavg()),'uptime':int(time.time()-psutil.boot_time()),'services':states,'mode':'live' if self.live else 'sandbox','php':[x for x in ['8.1','8.3'] if not self.live or Path('/usr/sbin/php-fpm'+x).exists()]}
        if action=='service':
            service=str(data.get('service')); op=str(data.get('op'))
            if service not in SERVICES or op not in ('restart','reload'): raise ValueError('Operasi layanan ditolak.')
            if self.live: run(['systemctl',op,service])
            return {'message':service+' '+op}
        if action=='logs':
            if data.get('domain'):
                name=domain(data['domain']); self.site(name)
                path=Path('/var/log/nginx/sypanel-'+name+'.error.log')
                return {'text':run(['tail','-n','150',str(path)]) if self.live and path.exists() else 'Belum ada log error situs.'}
            service=str(data.get('service','nginx'))
            if service not in SERVICES: raise ValueError('Layanan tidak dikenal.')
            return {'text':run(['journalctl','-u',service,'-n','100','--no-pager','--output=short-iso']) if self.live else 'Mode sandbox. Log layanan Ubuntu tersedia setelah instalasi.'}
        if action=='file': return self.file(data)
        if action=='restore': return self.restore(data)
        if action=='download':
            item=self.state.get('backups:'+str(data.get('name','')))
            if not item: raise ValueError('Cadangan tidak ditemukan.')
            p=self.backups/item['filename']
            if p.stat().st_size>64*1024**2: raise ValueError('Cadangan di atas 64 MiB diambil administrator dari /var/backups/sypanel.')
            return {'content':base64.b64encode(p.read_bytes()).decode(),'filename':p.name}
        if action=='db_export':
            item=self.state.get('databases:'+str(data.get('name','')))
            if not item: raise ValueError('Database tidak ditemukan.')
            content=run(['mariadb-dump','--single-transaction','--skip-lock-tables',item['name']],timeout=120) if self.live else '-- sandbox: no live database\n'
            if len(content)>64*1024**2: raise ValueError('Ekspor besar harus melalui SSH administrator.')
            return {'content':base64.b64encode(content.encode()).decode(),'filename':item['name']+'.sql'}
        if action=='ssl':
            name=domain(data['domain']); self.site(name)
            email=str(data.get('email',''))
            if not re.fullmatch(r'[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+',email): raise ValueError('Email ACME tidak valid.')
            if self.live: run(['certbot','certonly','--webroot','-w',str(self.site(name)),'-d',name,'--non-interactive','--agree-tos','--email',email],timeout=180)
            site=self.state['sites:'+name]; before=dict(site); site['ssl']=self.live
            try: self.web_apply(site)
            except Exception: self.state['sites:'+name]=before; raise
            self.save(); return {'message':'SSL diaktifkan.' if self.live else 'Simulasi SSL selesai. Sertifikat belum diterbitkan.','ssl':self.live}
        if '.' not in action: raise ValueError('Operasi tidak dikenal.')
        kind,op=action.split('.',1)
        if op=='update': return self.update(kind,data)
        if op not in ('create','delete'): raise ValueError('Operasi tidak dikenal.')
        if op=='create':
            d=validate(kind,data); key=kind+':'+d['name']
            if key in self.state: raise ValueError('Objek sudah ada di agent.')
            if kind!='sites': self.site(d['domain'])
        else:
            key=kind+':'+str(data.get('name','')); d=self.state.get(key)
            if not d or kind not in ('sites','databases','dns','mailboxes','forwarders','cron','sshkeys','redirects','backups'): raise ValueError('Objek agent tidak ditemukan.')
            if kind=='sites' and any(k!=key and x.get('domain')==d['domain'] for k,x in self.state.items()): raise ValueError('Hapus objek terkait situs terlebih dahulu.')
        old=dict(self.state); result={}
        if op=='delete': del self.state[key]
        else: self.state[key]=public(d)
        try:
            if kind=='sites':
                if op=='create': result=self.create_site(d)
                else:
                    conf=self.config('/etc/nginx/conf.d/sypanel-'+d['domain']+'.conf'); conf.unlink(missing_ok=True)
                    if self.live: run(['nginx','-t']); run(['systemctl','reload','nginx'])
                    php=d.get('php','static')
                    if php!='static':
                        self.config('/etc/php/'+php+'/fpm/pool.d/'+self.uid(d['domain'])+'.conf').unlink(missing_ok=True)
                        if self.live: run(['systemctl','reload','php'+php+'-fpm'])
                    self.config('/etc/ssh/sshd_config.d/sypanel-'+self.uid(d['domain'])+'.conf').unlink(missing_ok=True)
                    self.config('/etc/ssh/sypanel/'+self.uid(d['domain'])).unlink(missing_ok=True)
                    if self.live: run(['sshd','-t']); run(['systemctl','reload','ssh'])
                    result={'message':'Situs dinonaktifkan. Direktori dan user OS dipertahankan untuk pemulihan.'}
            elif kind=='databases':
                name=d['name']
                if not re.fullmatch(r'sy_[a-z][a-z0-9_]{2,23}',name): raise ValueError('Database tidak valid.')
                if self.live:
                    if op=='create':
                        # NO_BACKSLASH_ESCAPES plus quote doubling avoids SQL injection.
                        pw=d['password'].replace("'","''")
                        sql=f"SET SESSION sql_mode='NO_BACKSLASH_ESCAPES'; CREATE DATABASE `{name}` CHARACTER SET utf8mb4; CREATE USER '{name}'@'localhost' IDENTIFIED BY '{pw}'; GRANT ALL ON `{name}`.* TO '{name}'@'localhost';"
                    else: sql=f"DROP DATABASE IF EXISTS `{name}`; DROP USER IF EXISTS '{name}'@'localhost';"
                    try: run(['mariadb','--batch'],sql)
                    except ValueError: raise ValueError('Operasi MariaDB gagal. Periksa log server dan kemungkinan objek parsial.')
            elif kind=='dns': self.dns_apply()
            elif kind in ('mailboxes','forwarders'):
                if op=='create' and kind=='mailboxes':
                    hashed='{SHA512-CRYPT}'+run(['openssl','passwd','-6','-stdin'],d['password']+'\n').strip() if self.live else '{SIMULATED}'
                    self.state[key]['hash']=hashed
                self.mail_apply()
            elif kind=='cron':
                if op=='create': self.file({'domain':d['domain'],'op':'read','path':d['script']})
                self.cron_apply(d['domain'])
            elif kind=='sshkeys': self.keys_apply(d['domain'])
            elif kind=='redirects': self.web_apply(self.state['sites:'+d['domain']])
            elif kind=='backups':
                if op=='create': result=self.backup(d)
                else: (self.backups/d['filename']).unlink(missing_ok=True)
            if op=='create': self.state[key].update(result)
            self.save(); return dict(result,message=result.get('message','Operasi selesai.' if self.live else 'Simulasi selesai. Layanan server tidak diubah.'))
        except Exception:
            self.state=old
            if kind=='dns':
                try: self.dns_apply()
                except Exception: pass
            if kind in ('mailboxes','forwarders'):
                try: self.mail_apply()
                except Exception: pass
            raise
    def is_active(self,s):
        return subprocess.run(['systemctl','is-active','--quiet',s],capture_output=True).returncode==0

def main():
    path=os.environ.get('SYPANEL_SOCKET','/run/sypanel/agent.sock')
    Path(path).parent.mkdir(exist_ok=True); Path(path).unlink(missing_ok=True)
    user=pwd.getpwnam('sypanel'); server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    server.bind(path); os.chown(path,0,user.pw_gid); os.chmod(path,0o660); server.listen(20)
    while True:
        connection,_=server.accept()
        with connection:
            try:
                _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid!=user.pw_uid: raise ValueError('UID tidak diizinkan.')
                connection.settimeout(30); chunks=[]; size=0
                while True:
                    chunk=connection.recv(65536)
                    if not chunk: break
                    size+=len(chunk)
                    if size>24*1024**2: raise ValueError('Permintaan terlalu besar.')
                    chunks.append(chunk)
                request=json.loads(b''.join(chunks))
                result=Engine().dispatch(request['action'],request.get('data',{}))
                response={'ok':True,'result':result}
            except Exception as e: response={'ok':False,'error':str(e)}
            try: connection.sendall(json.dumps(response).encode())
            except OSError: pass

if __name__=='__main__': main()
