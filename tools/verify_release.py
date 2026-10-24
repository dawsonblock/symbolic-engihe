#!/usr/bin/env python3
"""Read-only bounded ZIP source verifier. Does not extract archive members."""
import hashlib
import json
import os
import stat
import sys
import zipfile
import zlib
from pathlib import PurePosixPath

MAX_ARCHIVE=512*1024*1024
MAX_MEMBERS=20000
MAX_MEMBER=64*1024*1024
MAX_TOTAL=256*1024*1024
MAX_MANIFEST=2*1024*1024
CHUNK=1024*1024


def _hash_member(z, info, *, limit):
    if info.file_size > limit:
        raise ValueError('archive member exceeds size limit: '+info.filename)
    digest=hashlib.sha256()
    total=0
    with z.open(info,'r') as stream:
        while True:
            block=stream.read(CHUNK)
            if not block: break
            total+=len(block)
            if total>limit:
                raise ValueError('archive member exceeds size limit: '+info.filename)
            digest.update(block)
    if total!=info.file_size:
        raise ValueError('archive member size mismatch: '+info.filename)
    return digest.hexdigest(),total


def verify(path):
    if os.path.getsize(path)>MAX_ARCHIVE:
        raise ValueError('archive exceeds compressed size limit')
    with zipfile.ZipFile(path) as z:
        infos=z.infolist()
        if len(infos)>MAX_MEMBERS:
            raise ValueError('archive contains too many members')
        names=[info.filename for info in infos]
        if len(names)!=len(set(names)):
            raise ValueError('archive has duplicate paths')
        total=0
        for info in infos:
            name=info.filename
            pure=PurePosixPath(name)
            mode=(info.external_attr>>16)&0xffff
            if (name.startswith('/') or '\\' in name or any(part in ('','.','..') for part in name.rstrip('/').split('/'))
                    or not name or (mode and stat.S_ISLNK(mode))):
                raise ValueError('archive has unsafe path or symlink: '+name)
            if info.file_size<0 or info.file_size>MAX_MEMBER:
                raise ValueError('archive member exceeds size limit: '+name)
            total+=info.file_size
        if total>MAX_TOTAL:
            raise ValueError('archive exceeds total uncompressed size limit')
        files=[info for info in infos if not info.is_dir()]
        prefixes={info.filename.split('/',1)[0] for info in files}
        if len(prefixes)!=1 or any('/' not in info.filename for info in files):
            raise ValueError('expected one project directory')
        prefix=next(iter(prefixes))+'/'
        manifest_path=prefix+'SOURCE_SHA256.json'
        manifests=[i for i in files if i.filename==manifest_path]
        if len(manifests)!=1:
            raise ValueError('missing exactly-one manifest')
        manifest_info=manifests[0]
        if manifest_info.file_size>MAX_MANIFEST:
            raise ValueError('manifest exceeds size limit')
        with z.open(manifest_info,'r') as stream:
            manifest_bytes=stream.read(MAX_MANIFEST+1)
        if len(manifest_bytes)>MAX_MANIFEST or len(manifest_bytes)!=manifest_info.file_size:
            raise ValueError('manifest size mismatch or limit exceeded')
        manifest=json.loads(manifest_bytes)
        if not isinstance(manifest,dict) or set(manifest)!={'schema','files'} or manifest['schema']!=1 or not isinstance(manifest['files'],dict):
            raise ValueError('invalid manifest schema')
        recorded=manifest['files']
        payload=[i for i in files if i.filename!=manifest_path]
        actual={}; streamed_total=manifest_info.file_size
        for info in payload:
            relative=info.filename[len(prefix):]
            pure=PurePosixPath(relative)
            if (not relative or pure.is_absolute() or '\\' in relative
                    or any(part in ('','.', '..') for part in relative.split('/'))):
                raise ValueError('unsafe source path: '+relative)
            limit=min(MAX_MEMBER,MAX_TOTAL-streamed_total)
            if limit<0:
                raise ValueError('archive exceeds total uncompressed size limit')
            actual[relative],size=_hash_member(z,info,limit=limit)
            streamed_total+=size
        if actual!=recorded:
            bad=sorted(set(actual)^set(recorded) | {k for k in set(actual)&set(recorded) if actual[k]!=recorded[k]})
            raise ValueError('SOURCE_SHA256 mismatch: '+', '.join(bad[:8]))
    archive_hash=hashlib.sha256()
    with open(path,'rb') as stream:
        for block in iter(lambda:stream.read(CHUNK),b''):
            archive_hash.update(block)
    return {'valid':True,'source_files':len(actual),'project':prefix[:-1],
            'zip_sha256':archive_hash.hexdigest()}


if __name__=='__main__':
    try:
        print(json.dumps(verify(sys.argv[1]),indent=2))
    except (ValueError,KeyError,zipfile.BadZipFile,RuntimeError,EOFError,json.JSONDecodeError,zlib.error,OSError) as exc:
        print(f'FAIL: {exc}',file=sys.stderr)
        raise SystemExit(1)
