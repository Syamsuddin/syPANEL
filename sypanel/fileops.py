"""Run as site UID. openat/O_NOFOLLOW prevents symlink escape and races."""
import os, stat, json, sys, base64, tarfile, io, shutil
from pathlib import PurePosixPath
MAX=16*1024*1024

def descend(root, parts):
    """Directory fd for root/parts, following no symlink on the way."""
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in parts:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd); fd=nxt
    except BaseException: os.close(fd); raise
    return fd

def store(fd, name, copy):
    f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o640,dir_fd=fd)
    with os.fdopen(f,'wb') as stream:
        s=os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1: raise ValueError('File khusus/link tidak diizinkan.')
        stream.truncate(0); copy(stream)

def operate(root, action, data):
    path=str(data.get('path','.'))
    parts=PurePosixPath(path).parts
    if path.startswith('/') or '..' in parts or '\x00' in path: raise ValueError('Path tidak valid.')
    fd=descend(root,parts if action=='list' else parts[:-1])
    try:
        name=parts[-1] if parts else '.'
        if action=='list':
            result=[]
            for item in sorted(os.listdir(fd)):
                s=os.stat(item,dir_fd=fd,follow_symlinks=False)
                result.append({'name':item,'dir':stat.S_ISDIR(s.st_mode),'link':stat.S_ISLNK(s.st_mode),'size':s.st_size,'modified':s.st_mtime})
            return result
        if action=='read':
            f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            with os.fdopen(f,'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise ValueError('Hanya file reguler.')
                content=stream.read(MAX+1)
            if len(content)>MAX: raise ValueError('Batas baca file 16 MiB.')
            return {'content':base64.b64encode(content).decode()}
        if action=='mkdir':
            os.mkdir(name,0o750,dir_fd=fd); return {'message':'Folder dibuat.'}
        if action=='write':
            content=base64.b64decode(data.get('content',''),validate=True)
            if len(content)>MAX: raise ValueError('Batas unggah 16 MiB.')
            store(fd,name,lambda stream:stream.write(content))
            return {'message':'File disimpan.'}
        if action=='delete':
            if name=='.': raise ValueError('Root tidak boleh dihapus.')
            s=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISDIR(s.st_mode): os.rmdir(name,dir_fd=fd)
            else: os.unlink(name,dir_fd=fd)
            return {'message':'Item dihapus. Folder harus kosong.'}
        raise ValueError('Aksi file tidak dikenal.')
    finally: os.close(fd)

def archive(root, out):
    """Write root as tar.gz. Run as the site UID, a symlink swapped in mid-walk exposes nothing the site cannot already read."""
    def keep(info): return info if info.isfile() or info.isdir() else None
    with tarfile.open(fileobj=out,mode='w|gz') as t: t.add(root,arcname='public_html',filter=keep)

def members(t):
    """Yield (member, path parts below public_html); only plain files and folders inside public_html pass."""
    for m in t:
        p=PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='public_html' or not (m.isdir() or m.isfile()): raise ValueError('Isi arsip tidak aman.')
        yield m,p.parts[1:]

def extract(root, source):
    with tarfile.open(fileobj=source,mode='r|gz') as t:
        for m,parts in members(t):
            if not parts: continue
            fd=descend(root,parts[:-1])
            try:
                if m.isfile(): store(fd,parts[-1],lambda stream:shutil.copyfileobj(t.extractfile(m),stream))
                else:
                    try: os.mkdir(parts[-1],0o750,dir_fd=fd)
                    except FileExistsError:
                        if not stat.S_ISDIR(os.stat(parts[-1],dir_fd=fd,follow_symlinks=False).st_mode): raise ValueError('Bukan folder: '+'/'.join(parts))
            finally: os.close(fd)

if __name__=='__main__':
    if sys.argv[2:] in (['archive'],['extract']):
        # Binary tar.gz on stdout (archive) or stdin (extract); errors go to stderr.
        try: archive(sys.argv[1],sys.stdout.buffer) if sys.argv[2]=='archive' else extract(sys.argv[1],sys.stdin.buffer)
        except Exception as e: sys.stderr.write(str(e)); sys.exit(1)
        sys.exit(0)
    try:
        d=json.load(sys.stdin)
        print(json.dumps({'ok':True,'result':operate(sys.argv[1],d['action'],d['data'])}))
    except Exception as e:
        print(json.dumps({'ok':False,'error':str(e)})); sys.exit(1)
