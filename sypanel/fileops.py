"""Run as site UID. openat/O_NOFOLLOW prevents symlink escape and races."""
import os, stat, json, sys, base64, tarfile, io
from pathlib import PurePosixPath
MAX=16*1024*1024

def operate(root, action, data):
    path=str(data.get('path','.'))
    parts=PurePosixPath(path).parts
    if path.startswith('/') or '..' in parts or '\x00' in path: raise ValueError('Path tidak valid.')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parents=parts if action=='list' else parts[:-1]
        for part in parents:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd); fd=nxt
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
            f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o640,dir_fd=fd)
            with os.fdopen(f,'wb') as stream:
                s=os.fstat(stream.fileno())
                if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1: raise ValueError('File khusus/link tidak diizinkan.')
                stream.truncate(0); stream.write(content)
            return {'message':'File disimpan.'}
        if action=='delete':
            if name=='.': raise ValueError('Root tidak boleh dihapus.')
            s=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISDIR(s.st_mode): os.rmdir(name,dir_fd=fd)
            else: os.unlink(name,dir_fd=fd)
            return {'message':'Item dihapus. Folder harus kosong.'}
        raise ValueError('Aksi file tidak dikenal.')
    finally: os.close(fd)

if __name__=='__main__':
    try:
        d=json.load(sys.stdin)
        print(json.dumps({'ok':True,'result':operate(sys.argv[1],d['action'],d['data'])}))
    except Exception as e:
        print(json.dumps({'ok':False,'error':str(e)})); sys.exit(1)
