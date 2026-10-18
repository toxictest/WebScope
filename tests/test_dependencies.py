#!/usr/bin/env python3
"""No package installation: dependency checks, plans, and privilege refusal only."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
count=0
def ok(value,label):
    global count
    if not value:raise AssertionError(label)
    count+=1;print('PASS '+label)

with tempfile.TemporaryDirectory(prefix='webscope-deps-') as temp:
    work=Path(temp);binpath=work/'bin';binpath.mkdir()
    source=(ROOT/'install_deps.sh').read_text()
    required=re.search(r'required=\(([^)]*)\)',source).group(1).split()
    for name in set(required+['uname']):
        if name=='dig':continue
        path=sys.executable if name=='python3' else shutil.which(name)
        if path:(binpath/name).symlink_to(path)
    marker=work/'package-manager-called'
    for manager in ['apt-get','dnf']:
        p=binpath/manager;p.write_text('#!/bin/bash\nprintf mocked > "'+str(marker)+'"\nexit 78\n');p.chmod(0o755)
    env=os.environ.copy();env['PATH']=str(binpath)
    def run(*args):return subprocess.run(['/bin/bash',str(ROOT/'install_deps.sh'),*args],env=env,text=True,capture_output=True,timeout=10)
    p=run('--help');ok(p.returncode==0 and not marker.exists(),'help causes no package-manager call')
    p=run('--plan');ok(p.returncode==0 and 'Plan only' in p.stdout and not marker.exists(),'installation plan is no-write/no-package-operation')
    p=run();ok(p.returncode==1 and 'MISSING: dig' in p.stdout,'default action detects missing dig without installing')
    p=run('--invalid');ok(p.returncode==2 and not marker.exists(),'unknown setup option rejected')
    p=run('--plan','--install');ok(p.returncode==2 and not marker.exists(),'ambiguous setup action rejected before installation')
    (binpath/'dig').write_text('#!/bin/bash\nexit 99\n');(binpath/'dig').chmod(0o755)
    p=run('--check');ok(p.returncode==0 and not marker.exists(),'runtime readiness checks command presence without querying DNS')
    p=run('--plan','--dev');ok(p.returncode==0 and 'normal-user venv' in p.stdout and not marker.exists(),'development plan does not create or install a venv')
    p=run('--install')
    ok((p.returncode==2 and not marker.exists()) if os.geteuid()!=0 else (p.returncode==78 and marker.exists()),'nonroot privilege guard or root mock boundary prevents real package install')
    packages=json.loads((ROOT/'packaging/dependencies.json').read_text())
    ok('bind9-dnsutils' in packages['apt'] and 'bind-utils' in packages['dnf'] and packages['automatic_install_default'] is False,'machine-readable dependency recipes match DNS package names')
    ok(not [x for x in (ROOT/'requirements.txt').read_text().splitlines() if x.strip() and not x.startswith('#')],'runtime pip requirements are intentionally empty')
print(f'RESULT: {count} passed, 0 failed')
