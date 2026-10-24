#!/usr/bin/env python3
"""Deterministic ZIP build with source SHA-256 manifest, excludes build caches."""
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT.parent / (ROOT.name + '.zip')
SKIP_DIRS = {'__pycache__', '.git', '.venv', 'dist', 'build', '.pytest_cache', '.mypy_cache'}
SKIP_EXTS = {'.pyc', '.pyo', '.sqlite3', '.db', '.log'}


def main():
    root = ROOT.resolve()
    paths = sorted((p for p in ROOT.rglob('*') if p.is_file() and not p.is_symlink()
                    and p.resolve().is_relative_to(root)
                    and not any(part in SKIP_DIRS or part.endswith('.egg-info') for part in p.relative_to(ROOT).parts)
                    and p.suffix not in SKIP_EXTS and p.name != 'SOURCE_SHA256.json'),
                   key=lambda x: x.relative_to(ROOT).as_posix())
    hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    manifest = (json.dumps({'schema':1,'files':hashes}, indent=2, sort_keys=True) + '\n').encode('utf8')
    (ROOT/'SOURCE_SHA256.json').write_bytes(manifest)
    with zipfile.ZipFile(DEST, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for path, data in [(p.relative_to(ROOT).as_posix(), p.read_bytes()) for p in paths] + [('SOURCE_SHA256.json',manifest)]:
            arc = f'{ROOT.name}/{path}'
            entry = zipfile.ZipInfo(arc, date_time=(2026, 10, 21, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (0o644 << 16)
            zipf.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    print(f'{DEST}: {len(paths)+1} files; {DEST.stat().st_size} bytes; sha256={hashlib.sha256(DEST.read_bytes()).hexdigest()}')

if __name__=='__main__':
    main()
