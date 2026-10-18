#!/usr/bin/env python3
"""Owned local services and deterministic DNS/provider fixtures only; no public scans."""
import contextlib, copy, hashlib, http.server, json, os, pathlib, shutil, signal, socket, ssl, subprocess, sys, tempfile, threading, time
R=pathlib.Path(__file__).resolve().parents[1]
COUNT=0

def ok(value,label):
 global COUNT
 if not value: raise AssertionError(label)
 COUNT+=1; print('PASS '+label,flush=True)

def imports():
 return 'set -uo pipefail; umask 077; '+ ';'.join('source '+str(p) for p in [R/'lib/common.sh',R/'lib/validation.sh',R/'lib/state_store.sh',R/'lib/network.sh',*sorted((R/'modules').glob('*.sh')),*sorted((R/'integrations').glob('*.sh'))])+'; '

def sh(code,env=None,timeout=20):
 return subprocess.run(['bash','-c',imports()+code],text=True,capture_output=True,env=env,timeout=timeout)

class Handler(http.server.BaseHTTPRequestHandler):
 requests=[]; hook_failures=0
 def log_message(self,*_): pass
 def do_HEAD(self):
  type(self).requests.append(('HEAD',self.path,self.headers.get('Host'),None))
  if self.path=='/slow': time.sleep(2)
  if self.path=='/redirect':
   self.send_response(302);self.send_header('Location','https://outside.invalid/');self.end_headers();return
  if self.path=='/redirect-secret':
   self.send_response(302);self.send_header('Location','https://outside.invalid/?token=SECRET_REDIRECT');self.end_headers();return
  if self.path=='/redirect-approved':
   self.send_response(302);self.send_header('Location','/jenkins');self.end_headers();return
  self.send_response(403 if self.path=='/denied' else 200)
  if self.path=='/jenkins':self.send_header('X-Jenkins','2.0')
  self.send_header('Server','Fixture<script>alert(1)</script>')
  self.send_header('Set-Cookie','session=SECRET_COOKIE; Secure')
  self.end_headers()
 def do_GET(self):
  type(self).requests.append(('GET',self.path,self.headers.get('Host'),None))
  if self.path=='/large':
   self.send_response(200);self.send_header('Content-Length','200000');self.end_headers()
   with contextlib.suppress(BrokenPipeError,ConnectionResetError):self.wfile.write(b'A'*200000)
   return
  self.do_HEAD()
  with contextlib.suppress(BrokenPipeError):self.wfile.write(b'<html><title>Controlled fixture landing page</title>PRIVATE_BODY_SENTINEL</html>')
 def do_POST(self):
  body=self.rfile.read(min(int(self.headers.get('Content-Length','0')),10000)).decode()
  type(self).requests.append(('POST',self.path,self.headers.get('Host'),body))
  if type(self).hook_failures:
   type(self).hook_failures-=1;self.send_response(503)
  else:self.send_response(200)
  self.end_headers()

def main():
 with tempfile.TemporaryDirectory(prefix='surfaceintel-test-') as temp:
  t=pathlib.Path(temp);bin=t/'bin';bin.mkdir(); mode=t/'dns-mode';mode.write_text('good');querylog=t/'queries';querylog.write_text('')
  dig=bin/'dig';dig.write_text('''#!/usr/bin/env bash
name=${@: -2:1}; type=${@: -1}; printf '%s %s\\n' "$name" "$type" >> "$SI_DNS_LOG"
mode=$(cat "$SI_DNS_MODE")
if [[ $mode == servfail ]]; then echo ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1'; exit 0; fi
if [[ $mode == nxdomain ]]; then echo ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1'; exit 0; fi
echo ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1'
if [[ $name == alias.example.test && $type == A ]]; then printf '%s. 60 IN CNAME vendor.invalid.\\n' "$name"; fi
if [[ $name == mixed.example.test && $type == AAAA ]]; then printf '%s. 60 IN AAAA fd00::1\\n' "$name"; fi
if [[ $type == A ]]; then ip=127.0.0.1; [[ $mode != changed ]] || ip=127.0.0.2; [[ $name != metadata.example.test ]] || ip=169.254.169.254; printf '%s. 60 IN A %s\\n' "$name" "$ip"; fi
if [[ $type == TXT ]]; then printf '%s. 60 IN TXT "SECRET_TXT_VALUE"\\n' "$name"; fi
''');dig.chmod(0o755)
  env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'],SI_DNS_MODE=str(mode),SI_DNS_LOG=str(querylog),HTTPS_PROXY='http://127.0.0.1:1',HTTP_PROXY='http://127.0.0.1:1',ALL_PROXY='http://127.0.0.1:1')
  http_srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);port=http_srv.server_address[1]
  # Use a separate variable: the module name is retained for the second server below.
  import http.server as hs
  key=t/'key.pem';cert=t/'cert.pem'
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','14','-subj','/CN=api.example.test','-addext','subjectAltName=DNS:api.example.test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
  https=hs.ThreadingHTTPServer(('127.0.0.1',0),Handler);tlsport=https.server_address[1]
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(str(cert),str(key));https.socket=ctx.wrap_socket(https.socket,server_side=True)
  for server in (http_srv,https):threading.Thread(target=server.serve_forever,daemon=True).start()
  try:
   base=f'http://api.example.test:{port}';secure=f'https://api.example.test:{tlsport}'
   scope=t/'scope.conf';scope.write_text('organization=fixture\ndomain_tree=example.test\ncidr=127.0.0.0/8\n'+''.join('endpoint='+base+p+'\n' for p in ['/','/jenkins','/admin','/login','/redirect','/redirect-secret'])+'endpoint='+secure+'/\nexclude_tree=excluded.example.test\n')
   policy=t/'policy.conf';policy.write_text('config_version=test1\ndns_rate=50\nhttp_rate=20\ntimeout=2\nmax_duration=300\nallow_nonpublic=true\nca_file='+str(cert)+'\n')
   out=t/'reports'
   def cli(*args,scope_file=scope,policy_file=policy,output=out,timeout=90):
    return subprocess.run([str(R/'surfaceintel.sh'),'--scope',str(scope_file),'--config',str(policy_file),'--output',str(output),*map(str,args)],text=True,capture_output=True,env=env,timeout=timeout)
   # Pure parsing/scope/CIDR safety cases.
   common='ROOTS=(example.test); EXCLUDE_TREES=(excluded.example.test); '
   for name,want in [('example.test',True),('a.example.test',True),('badexample.test',False),('example.test.attacker.invalid',False),('excluded.example.test',False),('a.excluded.example.test',False),('example.test.',False),('*.example.test',False),('bad;touch.example.test',False)]:
    rr=sh(common+'host_scope '+json.dumps(name),env);ok((rr.returncode==0)==want,'exact host scope '+name)
   for ip,want in [('8.8.8.8',True),('1.1.1.1',True),('127.0.0.1',False),('10.0.0.1',False),('172.16.1.2',False),('192.168.1.1',False),('169.254.169.254',False),('100.100.100.200',False),('0.0.0.0',False),('224.0.0.1',False),('0127.0.0.1',False),('2130706433',False),('0x7f000001',False),('2001:4860:4860::8888',True),('::1',False),('fe80::1',False),('fd00::1',False),('ff02::1',False),('::ffff:127.0.0.1',False),('::ffff:7f00:1',False),('64:ff9b::a9fe:a9fe',False),('2001:db8::1',False),('fe80::1%eth0',False)]:
    rr=sh('ip_allowed '+json.dumps(ip)+' false',env);ok((rr.returncode==0)==want,'destination policy '+ip)
   for ip,cidr,want in [('192.168.2.3','192.168.0.0/16',True),('192.169.2.3','192.168.0.0/16',False),('2001:db8:abcd::1','2001:db8::/32',True),('2001:db9::1','2001:db8::/32',False),('::1','::1/128',True),('::2','::1/128',False),('10.1.2.3','10.0.0.0/9',True),('10.129.2.3','10.0.0.0/9',False)]:
    rr=sh('in_cidr '+json.dumps(ip)+' '+json.dumps(cidr),env);ok((rr.returncode==0)==want,'CIDR prefix '+ip+' '+cidr)
   for ip in ['127.0.0.1','::1']:
    rr=sh('CIDRS=(127.0.0.0/8 ::1/128); ALLOW_NONPUBLIC=true; ip_allowed '+json.dumps(ip)+' true',env);ok(rr.returncode==0,'explicit legitimate local authorization '+ip)
   for ip in ['169.254.169.254','fd00:ec2::254','100.100.100.200','169.254.170.2','169.254.0.23','168.63.129.16','fd00:ec2::23']:
    rr=sh('CIDRS=(0.0.0.0/0 ::/0); ALLOW_NONPUBLIC=true; ip_allowed '+json.dumps(ip)+' true',env);ok(rr.returncode!=0,'metadata remains forbidden under broad CIDR '+ip)
   for url,want in [('https://api.example.test/',True),('http://[::1]:8080/',True),('http://0127.0.0.1/',False),('http://0x7f.0.0.1/',False),('http://2130706433/',False),('https://api.example.test@evil.invalid/',False),('file:///etc/passwd',False),('https://api.example.test/?token=secret',False),('https://api.example.test/%2e%2e/x',False),('https://api.example.test/a/../b',False),('https://api.example.test:99999/',False),('https://api.example.test:/',False),('https://api.example.test/;touch',False)]:
    rr=sh('parse_url '+json.dumps(url),env);ok((rr.returncode==0)==want,'strict URL parser '+url)
   before=len(Handler.requests);r=cli('--dry-run');ok(r.returncode==0 and not out.exists() and len(Handler.requests)==before and not querylog.read_text(),'dry run validates without network or storage')
   r=cli('--http-checks','--update-baseline');ok(r.returncode==0,'full controlled local audit completes: '+r.stderr)
   runs=sorted((out/'fixture').glob('run-*'));run=runs[-1]
   inventory=json.loads((run/'inventory.json').read_text());findings=json.loads((run/'findings.json').read_text())['findings']
   ok(inventory['completion']=='complete','complete scan status')
   ok(any(x['kind']=='tls' and 'WITHIN_15_DAYS' in x['evidence'] for x in inventory['assets']),'real local TLS certificate expiry collected')
   ok(any(x['category']=='CERTIFICATE_LIFECYCLE' and x['severity']=='CRITICAL' for x in findings),'default 15-day critical lifecycle priority')
   ok(any(x['category']=='MANAGEMENT_INTERFACE_POTENTIAL' for x in findings),'Jenkins response header is potential exposure')
   ok(any(x['category']=='ADMIN_ROUTE_POTENTIAL' for x in findings),'admin route is conservative heuristic')
   ok(not any('CONFIRMED_UNAUTHENTICATED' in x['status'] for x in findings),'200/admin/login never falsely confirms unauthenticated privileges')
   ok(not any(x['asset'].endswith('/login') for x in findings),'ordinary login endpoint is not a dashboard finding')
   ok(not any(x[2]=='outside.invalid' for x in Handler.requests),'external redirects never followed')
   alltext=''.join(p.read_text() for p in run.iterdir() if p.is_file())
   for secret in ['SECRET_COOKIE','SECRET_REDIRECT','SECRET_TXT_VALUE','PRIVATE_BODY_SENTINEL','PRIVATE KEY']:
    ok(secret not in alltext,'sensitive data omitted: '+secret)
   ok('<script>alert(1)</script>' not in (run/'summary.html').read_text(),'HTML escapes hostile server metadata')
   ok('&lt;script&gt;' in (run/'summary.html').read_text(),'escaped evidence remains visible in HTML')
   ok(all(p.stat().st_mode&0o777==0o600 for p in run.iterdir() if p.is_file()),'all report files private')
   baseline=out/'fixture/state/baseline.tsv';before_baseline=baseline.read_bytes()
   r=cli('--http-checks');ok(r.returncode==0,'repeat audit succeeds')
   run2=sorted((out/'fixture').glob('run-*'))[-1]
   ok('KNOWN_FINDING' in (run2/'delta.tsv').read_text(),'repeat evidence is known risk')
   ok('NEW_ASSET' not in (run2/'delta.tsv').read_text(),'timestamps do not invent new assets')
   ok(baseline.read_bytes()==before_baseline,'baseline not replaced without explicit flag')
   mode.write_text('servfail');r=cli('--http-checks','--update-baseline');ok(r.returncode==3,'temporary DNS failures mark scan partial')
   failedrun=sorted((out/'fixture').glob('run-*'))[-1]
   ok(baseline.read_bytes()==before_baseline,'partial scan preserves successful baseline byte for byte')
   ok('SCOPE_REMOVED' not in (failedrun/'delta.tsv').read_text(),'DNS failure is not asset removal')
   mode.write_text('good')
   dnsout=t/'dnsreports';r=cli('--dns-only','--update-baseline',output=dnsout);ok(r.returncode==0,'DNS-only baseline established')
   mode.write_text('changed');r=cli('--dns-only',output=dnsout);ok(r.returncode==0,'DNS change collection succeeds')
   dr=sorted((dnsout/'fixture').glob('run-*'))[-1];ok('EVIDENCE_CHANGED' in (dr/'delta.tsv').read_text(),'address drift detected')
   mode.write_text('nxdomain');r=cli('--dns-only',output=dnsout);dr=sorted((dnsout/'fixture').glob('run-*'))[-1];ok(r.returncode==0 and 'NEWLY_UNRESOLVED' in (dr/'delta.tsv').read_text(),'NXDOMAIN is unresolved, not removal')
   mode.write_text('good')
   # Every resolved address and CNAME is checked before any pinned connection.
   for host,reason in [('metadata.example.test','DESTINATION_NOT_AUTHORIZED'),('mixed.example.test','DESTINATION_NOT_AUTHORIZED'),('alias.example.test','UNAPPROVED_CNAME')]:
    scratch=t/host;scratch.mkdir();rr=sh(common+f'WORK={scratch}; CIDRS=(127.0.0.0/8); ALLOW_NONPUBLIC=true; DNS_RATE=50; resolve_destination {host} asset; echo "$DEST_REASON"',env)
    ok(reason in rr.stdout,'preconnection guard '+host)
   # Real owned-service timeout, TLS hostname mismatch, and HTTP redirects.
   slow=t/'slow.conf';slow.write_text('organization=slow\nhost=api.example.test\ncidr=127.0.0.0/8\nendpoint='+base+'/slow\n')
   started=time.monotonic();r=cli('--http-checks','--timeout','1',scope_file=slow,output=t/'slowout');ok(r.returncode==3 and time.monotonic()-started<15,'owned HTTP service request deadline bounded')
   wrong=t/'wrong.conf';wrong.write_text('organization=wrong\nhost=wrong.example.test\ncidr=127.0.0.0/8\nendpoint='+secure.replace('api.','wrong.')+'/\n')
   r=cli('--tls-only',scope_file=wrong,output=t/'wrongout');wr=sorted((t/'wrongout/wrong').glob('run-*'))[-1]
   wf=json.loads((wr/'findings.json').read_text())['findings'];ok(any('hostname_mismatch=true' in x['evidence'] for x in wf),'real local certificate hostname mismatch detected')
   # Cloud provider classification with synthetic response headers, never real cloud.
   headers=t/'headers';body=t/'body';body.write_text('<ListBucketResult><MaxKeys>0</MaxKeys><KeyCount>0</KeyCount></ListBucketResult>')
   cases=[('s3','object',200,'x-amz-request-id: fixture\netag: "abc"\n','false','PUBLIC_OBJECT_READ_CONFIRMED'),('azure','object',200,'x-ms-request-id: fixture\nx-ms-blob-type: BlockBlob\n','false','PUBLIC_OBJECT_READ_CONFIRMED'),('gcs','object',200,'x-goog-generation: 123\n','false','PUBLIC_OBJECT_READ_CONFIRMED'),('s3','bucket',200,'x-amz-request-id: fixture\n','false','INDETERMINATE'),('s3','bucket',200,'x-amz-request-id: fixture\n','true','PUBLIC_LISTING_CONFIRMED'),('s3','object',200,'Server: unrelated\n','false','INDETERMINATE'),('azure','object',403,'x-ms-request-id: fixture\n','false','ACCESS_DENIED'),('gcs','object',401,'x-guploader-uploadid: fixture\n','false','AUTH_REQUIRED'),('s3','bucket',404,'x-amz-request-id: fixture\n','false','NOT_FOUND')]
   for provider,kind,code,h,listing,expected in cases:
    headers.write_text(h);rr=sh(f'HTTP_HEADERS={headers}; HTTP_BODY={body}; cloud_classify {provider} {kind} {code} {listing}; echo "$CLOUD_STATUS"',env)
    ok(rr.stdout.strip()==expected,f'provider classification {provider} {kind} {code} {listing}')
   body.write_text('<ListBucketResult><MaxKeys>0</MaxKeys><Contents><Key>not-permitted</Key></Contents></ListBucketResult>');headers.write_text('x-amz-request-id: fixture\n')
   rr=sh(f'HTTP_HEADERS={headers}; HTTP_BODY={body}; cloud_classify s3 bucket 200 true; echo "$CLOUD_STATUS"',env);ok(rr.stdout.strip()=='INDETERMINATE','unexpected object entries cannot confirm zero-object verification')
   for seconds,bucket in [(-1,'EXPIRED'),(1,'WITHIN_1_DAY'),(86400,'WITHIN_1_DAY'),(86401,'WITHIN_7_DAYS'),(604801,'WITHIN_15_DAYS'),(1296001,'WITHIN_30_DAYS'),(2592001,'VALID')]:
    rr=sh(f'tls_bucket {seconds}; echo "$TLS_BUCKET"',env);ok(rr.stdout.strip()==bucket,'TLS boundary '+str(seconds))
   # Alerts via actual local HTTP receiver, with secrets protected and retries bounded.
   alert=t/'alerts.conf';alert.write_text('organization=fixture\napproved_host=127.0.0.1\nslack_env=SI_TEST_WEBHOOK\nminimum_severity=HIGH\ncooldown_seconds=86400\nretries=1\n');alert.chmod(0o600)
   ap=t/'alert-policy.conf';ap.write_text(policy.read_text()+'alert_config='+str(alert)+'\n')
   env['SI_TEST_WEBHOOK']=f'http://127.0.0.1:{port}/hook/WEBHOOK_SECRET_TOKEN'
   Handler.hook_failures=1;post_before=sum(x[0]=='POST' for x in Handler.requests)
   alertout=t/'alertout';r=cli('--http-checks','--update-baseline',policy_file=ap,output=alertout);ok(r.returncode==0,'webhook transient failure does not break local audit')
   posts=[x for x in Handler.requests if x[0]=='POST'];ok(len(posts)>post_before+1,'bounded retry delivered to owned webhook receiver')
   for post in posts:json.loads(post[3])
   ok(True,'webhook payload JSON valid')
   aroot=alertout/'fixture';ar=sorted(aroot.glob('run-*'))[-1]
   ok('DELIVERED' in (ar/'alert-delivery.tsv').read_text(),'delivery success recorded without destination')
   snapshot=len(posts);r=cli('--http-checks',policy_file=ap,output=alertout);ok(r.returncode==0,'deduplicated alert repeat completes')
   ok(sum(x[0]=='POST' for x in Handler.requests)==snapshot,'unchanged alerts deduplicated inside cooldown')
   ok('WEBHOOK_SECRET_TOKEN' not in ''.join(p.read_text() for p in aroot.rglob('*') if p.is_file()),'webhook secret absent from every report/state/log')
   for provider in ['slack','discord','teams']:
    rr=sh('payload_'+provider+' '+json.dumps('fixture "quote" <script>'),env);json.loads(rr.stdout);ok(rr.returncode==0,'provider payload '+provider)
   # Malformed inputs must fail before networking.
   for value in ['organization=bad;touch\n','organization=fixture\ndomain_tree=example.test.attacker.invalid\nendpoint='+base+'/\n','organization=fixture\nhost=example.test\ncommand=touch /tmp/NEVER\n','organization=fixture\ndomain_tree=*.example.test\n']:
    bad=t/'bad.conf';bad.write_text(value);n=len(Handler.requests);r=cli('--dry-run',scope_file=bad);ok(r.returncode==2 and len(Handler.requests)==n,'malformed or unauthorized configuration rejected')
   for args in [('--timeout','0'),('--concurrency','99'),('--rate-limit','0'),('--report','xml'),('--dns-only','--http-checks'),('--dns-only','--tls-only')]:
    ok(cli(*args).returncode==2,'CLI validates '+repr(args))
   # Passive-only does not use resolver or target HTTP/TLS.
   q=querylog.read_text();n=len(Handler.requests);r=cli('--passive-only',output=t/'passive');ok(r.returncode==0 and querylog.read_text()==q and len(Handler.requests)==n,'passive and active validation separated')
   # Lock contention and cleanup; controlled slow service ensures overlap.
   lockout=t/'lockout';proc=subprocess.Popen([str(R/'surfaceintel.sh'),'--scope',str(slow),'--config',str(policy),'--output',str(lockout),'--http-checks'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   deadline=time.monotonic()+10
   while time.monotonic()<deadline and not (lockout/'slow/state/run.lock').exists():time.sleep(.02)
   rr=cli('--http-checks',scope_file=slow,output=lockout);ok(rr.returncode==75,'overlapping customer runs refused')
   proc.send_signal(signal.SIGTERM);proc.communicate(timeout=15);ok(proc.returncode==143,'graceful SIGTERM exit')
   ok(not (lockout/'slow/state/run.lock').exists(),'owned run lock released on interruption')
   intruns=list((lockout/'slow').glob('run-*'));ok(any('\tinterrupted\t' in (p/'state.tsv').read_text() for p in intruns if (p/'state.tsv').exists()),'interrupted scan recorded explicitly')
   # Stable headers and malformed/foreign baseline checks.
   foreign=t/'foreign.tsv';foreign.write_bytes(before_baseline.replace(b'\tfixture\t',b'\tother\t',1));r=cli('--baseline',foreign,'--dns-only',output=t/'foreignout');ok(r.returncode==2,'cross-customer baseline rejected')
   malformed=t/'malformed.tsv';malformed.write_text('$(touch '+str(t/'EXECUTED')+')\n');r=cli('--baseline',malformed,'--dns-only',output=t/'badbaseline');ok(r.returncode==2 and not (t/'EXECUTED').exists(),'baseline never executed')
   # Schema contracts and explicit structured finding properties.
   try:
    import jsonschema
   except ImportError:
    print('SKIP optional JSON Schema validation: jsonschema unavailable')
   else:
    for name in ['inventory','findings']:
     schema=json.loads((R/'schemas'/(name+'.schema.json')).read_text())
     jsonschema.Draft202012Validator(schema).validate(json.loads((run/(name+'.json')).read_text()))
     ok(True,'full JSON Schema validation '+name)
   ok(all(all(k in x for k in ['asset_id','category','confidence','verification_method','baseline_change','remediation','policy_reference']) for x in findings),'findings carry structured evidence and policy fields')
   # Actual IPv6 local transport if the kernel supports an owned ::1 listener.
   class V6(hs.ThreadingHTTPServer):address_family=socket.AF_INET6
   try:v6=V6(('::1',0),Handler)
   except OSError:print('SKIP native IPv6 loopback unavailable (IPv6 policy tests still ran)')
   else:
    threading.Thread(target=v6.serve_forever,daemon=True).start()
    try:
     vscope=t/'v6.conf';vscope.write_text('organization=v6fixture\nhost=::1\ncidr=::1/128\nendpoint=http://[::1]:'+str(v6.server_address[1])+'/\n')
     vr=cli('--http-checks',scope_file=vscope,output=t/'v6out')
     ok(vr.returncode==0,'real controlled IPv6 HTTP endpoint works without resolver ambiguity: '+vr.stderr)
    finally:v6.shutdown();v6.server_close()
   # No jq or Python on PATH: the core Bash engine still emits valid JSON.
   minimal=t/'minimal-bin';minimal.mkdir()
   for tool in ['bash','dirname','date','curl','sha256sum','sort','awk','sed','grep','cut','diff','cmp','tr','stat','mktemp','find','head','tail','wc','mkdir','id','cp','mv','rm','rmdir','sleep','cat','basename']:
    path=shutil.which(tool)
    if path:(minimal/tool).symlink_to(path)
   menv=dict(env,PATH=str(minimal));mout=t/'minimal-out'
   rr=subprocess.run([str(R/'surfaceintel.sh'),'--scope',str(scope),'--config',str(policy),'--passive-only','--output',str(mout)],env=menv,capture_output=True,text=True,timeout=30)
   ok(rr.returncode==0,'core runtime works with Python/jq absent from PATH: '+rr.stderr)
   json.loads(next((mout/'fixture').glob('run-*/inventory.json')).read_text());ok(True,'native Bash serializer emits valid JSON without jq')
   # Approve-only redirect following; every hop remains in the configured endpoint set.
   follow=t/'follow.conf';follow.write_text(policy.read_text()+'follow_redirects=true\n')
   fs=t/'follow-scope.conf';fs.write_text('organization=followfixture\nhost=api.example.test\ncidr=127.0.0.0/8\nendpoint='+base+'/redirect-approved\nendpoint='+base+'/jenkins\n')
   rr=cli('--http-checks',scope_file=fs,policy_file=follow,output=t/'followout');ok(rr.returncode==0,'approved redirect chain completes')
   fr=next((t/'followout/followfixture').glob('run-*/inventory.json'));fo=json.loads(fr.read_text())
   ok(any(x['asset'].endswith('/redirect-approved') and 'hops=1' in x['evidence'] for x in fo['assets']),'redirect destination revalidated and followed once')
   # Request rate limiter: observed interval, not just parsed configuration.
   rr=sh('HTTP_RATE=5; a=$(date +%s%N); rate_wait http; rate_wait http; b=$(date +%s%N); echo $((b-a))',env)
   ok(rr.returncode==0 and int(rr.stdout.strip())>=180000000,'HTTP rate limiter enforces spacing')
   # Permanent provider errors are local delivery failures, not audit failures.
   Handler.hook_failures=100;failedalerts=t/'failed-alerts'
   rr=cli('--http-checks',policy_file=ap,output=failedalerts)
   fa=next((failedalerts/'fixture').glob('run-*/alert-delivery.tsv'))
   ok(rr.returncode==0 and 'FAILED' in fa.read_text(),'webhook outage recorded while local audit continues')
   Handler.hook_failures=0
   # Runtime cloud module does not enumerate or GET objects by default.
   cloudwork=t/'cloud-unit';cloudwork.mkdir()
   for name in ['records.tsv','errors.tsv']: (cloudwork/name).write_text('')
   headers.write_text('x-amz-request-id: fixture\netag: "fixture"\n')
   code=f'WORK={cloudwork}; CLOUDS=("s3|object|https://approved-bucket.s3.us-east-1.amazonaws.com/probe.txt"); request() {{ printf "%s\n" "$3" > "{cloudwork}/method"; HTTP_CODE=200; HTTP_HEADERS={headers}; HTTP_BODY={body}; }}; cloud_storage'
   rr=sh(code,env);ok(rr.returncode==0 and (cloudwork/'method').read_text().strip()=='HEAD','cloud object verification requests HEAD, never GET')
   ok('PUBLIC_OBJECT_READ_CONFIRMED' in (cloudwork/'records.tsv').read_text(),'cloud module preserves provider-specific HEAD evidence')
   # Invalid namespace or cloud endpoint cannot be smuggled into the provider adapter.
   for resource in ['s3|bucket|https://bucket.s3.attacker.invalid/','azure|bucket|https://account.blob.core.windows.net/container/../other','gcs|object|https://storage.googleapis.com/bucket/x?token=secret']:
    rr=sh('validate_cloud '+json.dumps(resource),env);ok(rr.returncode!=0,'cloud namespace URL rejected '+resource.split('|')[0])
   # Missing optional TLS dependency is visible, not a clean result.
   depwork=t/'dep-unit';depwork.mkdir();(depwork/'records.tsv').write_text('');(depwork/'errors.tsv').write_text('')
   code=common+f'WORK={depwork}; command() {{ if [[ $1 == -v && $2 == openssl ]]; then return 1; fi; builtin command "$@"; }}; tls_one "{secure}/"'
   rr=sh(code,env);ok('UNAVAILABLE' in (depwork/'records.tsv').read_text(),'missing TLS utility produces unavailable evidence')
   # Bad baselines: duplicate stable IDs, invalid state, control bytes and oversize input.
   for label,contents in [('duplicate',before_baseline+before_baseline.splitlines(keepends=True)[1]),('invalid-status',before_baseline.replace(b'\tCANDIDATE\t',b'\tinvalid-state\t',1)),('NUL',before_baseline+b'\0'),('bad-version',before_baseline.replace(b'SURFACEINTEL_STATE\t1',b'SURFACEINTEL_STATE\t9',1))]:
    path=t/(label+'.tsv');path.write_bytes(contents);rr=sh(f'ORG=fixture; validate_state {path}',env);ok(rr.returncode!=0,'invalid historical state rejected '+label)
   # A live interrupted update cannot replace a previous successful baseline.
   original=baseline.read_bytes()
   proc=subprocess.Popen([str(R/'surfaceintel.sh'),'--scope',str(scope),'--config',str(policy),'--output',str(out),'--http-checks','--update-baseline'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
   deadline=time.monotonic()+10
   while time.monotonic()<deadline and not list((out/'fixture').glob('run-*-'+str(proc.pid))):time.sleep(.02)
   proc.send_signal(signal.SIGINT);proc.communicate(timeout=15)
   ok(proc.returncode==130,'SIGINT has documented exit code')
   ok(baseline.read_bytes()==original,'interrupted explicit update preserves successful baseline')
   # Renewal produces a resolved lifecycle observation, not merely a missing finding.
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','60','-subj','/CN=api.example.test','-addext','subjectAltName=DNS:api.example.test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
   ctx.load_cert_chain(str(cert),str(key))
   rr=cli('--http-checks');ok(rr.returncode==0,'renewed local TLS certificate collected')
   renew=sorted((out/'fixture').glob('run-*'))[-1]
   ok(any(line.startswith('RESOLVED') and 'CERTIFICATE_LIFECYCLE' in line for line in (renew/'delta.tsv').read_text().splitlines()),'certificate renewal resolves prior lifecycle finding with positive evidence')
   # Retention prunes only tool-created run directories; reports and baseline archives stay separate.
   retain=t/'retain-policy.conf';retain.write_text(policy.read_text()+'retention_runs=2\nretention_baselines=2\n')
   retainout=t/'retained'
   for _ in range(4):
    rr=cli('--passive-only','--update-baseline',policy_file=retain,output=retainout)
    ok(rr.returncode==0,'opt-in scheduled-equivalent baseline update')
   ok(len(list((retainout/'fixture').glob('run-*')))==2,'configured report retention enforced')
   ok(len(list((retainout/'fixture/state').glob('baseline-prev-*')))==2,'previous baseline retention enforced')
   # Additional ambiguity and policy regression checks.
   for address in ['1.2.3.4.','::1:',':1::2','1:2:3:4:5:6:7:8:','0x7f.0.0.1']:
    ok(sh('ip_expand '+json.dumps(address),env).returncode!=0,'ambiguous address rejected '+address)
   for cidr in ['192.168.1.1/24','2001:db8::1/64','127.0.0.1/8']:
    ok(sh('cidr_valid '+json.dumps(cidr),env).returncode!=0,'non-network-aligned CIDR rejected '+cidr)
   for address in ['64:ff9b:1::a9fe:a9fe','4000::1']:
    ok(sh('ip_allowed '+json.dumps(address)+' false',env).returncode!=0,'special/unallocated IPv6 not treated as public '+address)
   crit=t/'critical-novelty.conf';crit.write_text(policy.read_text()+'severity_new_asset=CRITICAL\n')
   ok(cli('--dry-run',policy_file=crit).returncode==2,'novelty alone cannot be elevated to critical')
   custom=t/'severity-policy.conf';custom.write_text(policy.read_text()+'severity_management_interface_potential=MEDIUM\n')
   sr=cli('--http-checks',policy_file=custom,output=t/'severityout');sf=next((t/'severityout/fixture').glob('run-*/findings.json'))
   ok(sr.returncode==0 and any(x['category']=='MANAGEMENT_INTERFACE_POTENTIAL' and x['severity']=='MEDIUM' for x in json.loads(sf.read_text())['findings']),'explicit policy severity override works')
   # Low-severity drift/candidate notices are alertable without inventing vulnerabilities.
   infoalert=t/'info-alert.conf';infoalert.write_text('organization=fixture\napproved_host=127.0.0.1\nslack_env=SI_TEST_WEBHOOK\nminimum_severity=INFO\ncategory=NEW_ASSET\nretries=0\n');infoalert.chmod(0o600)
   infopolicy=t/'info-policy.conf';infopolicy.write_text(policy.read_text()+'alert_config='+str(infoalert)+'\n')
   n=len(Handler.requests);rr=cli('--dns-only',policy_file=infopolicy,output=t/'info-alerts')
   notices=[x for x in Handler.requests[n:] if x[0]=='POST']
   ok(rr.returncode==0 and notices and all('NEW_ASSET' in x[3] for x in notices),'category-filtered INFO candidate/delta alerts delivered')
   n=sum(x[0]=='POST' for x in Handler.requests);env['SI_TEST_WEBHOOK']=f'http://127.0.0.1:{port}/hook/DIFFERENT_DESTINATION_SECRET'
   rr=cli('--http-checks',policy_file=ap,output=alertout)
   ok(rr.returncode==0 and sum(x[0]=='POST' for x in Handler.requests)>n,'changed alert destination has independent deduplication state')
   # Static malicious historical symlinks cannot redirect writes outside state.
   poison=t/'poison';state=poison/'fixture/state';state.mkdir(parents=True)
   for q in [poison,poison/'fixture',state]:q.chmod(0o700)
   victim=t/'never-create';(state/'organization').symlink_to(victim)
   rr=cli('--passive-only',output=poison);ok(rr.returncode==2 and not victim.exists(),'dangling organization-marker symlink rejected without write-through')
   poison2=t/'poison2';state2=poison2/'fixture/state';state2.mkdir(parents=True)
   for q in [poison2,poison2/'fixture',state2]:q.chmod(0o700)
   (state2/'organization').write_text('fixture\n');victim2=t/'untouched';victim2.write_text('DO NOT TOUCH');(state2/'delivered.tsv').symlink_to(victim2)
   rr=cli('--dns-only',policy_file=infopolicy,output=poison2)
   ok(rr.returncode==0 and victim2.read_text()=='DO NOT TOUCH','delivery-cache symlink cannot overwrite unrelated files')
   # Installer and scheduled command wrappers remain explicit opt-in.
   prefix=t/'installed';installer=[str(R/'packaging/install.sh'),'--prefix',str(prefix)]
   rr=subprocess.run(installer,capture_output=True,text=True);ok(rr.returncode==0 and not prefix.exists(),'installer default is a no-write plan')
   rr=subprocess.run(installer+['--confirm-install'],capture_output=True,text=True);ok(rr.returncode==0 and (prefix/'.surfaceintel-install').exists(),'confirmed install uses only a new owned test directory')
   rr=subprocess.run([str(prefix/'surfaceintel.sh'),'--scope',str(scope),'--config',str(policy),'--dry-run'],env=env,capture_output=True,text=True);ok(rr.returncode==0,'installed executable validates a plan')
   ok(subprocess.run(installer+['--confirm-install'],capture_output=True).returncode==2,'installer will not overwrite existing release')
   ok(subprocess.run([str(R/'packaging/install.sh'),'--prefix','/','--confirm-install'],capture_output=True).returncode==2,'installer rejects root destination')
   n=len(Handler.requests)
   rr=subprocess.run(['timeout','10',str(R/'surfaceintel.sh'),'--scope',str(scope),'--config',str(policy),'--passive-only','--output',str(t/'scheduled-wrapper'),'--update-baseline'],env=env,capture_output=True,text=True)
   ok(rr.returncode==0 and len(Handler.requests)==n,'scheduled command with external wall-clock supervisor works')
   # Optional previews collect only bounded sanitized titles, not page contents.
   preview=t/'preview-policy.conf';preview.write_text(policy.read_text()+'http_body_preview=true\n')
   ps=t/'preview-scope.conf';ps.write_text('organization=previewfixture\nhost=api.example.test\ncidr=127.0.0.0/8\nendpoint='+base+'/\n')
   rr=cli('--http-checks',scope_file=ps,policy_file=preview,output=t/'preview-out')
   pr=next((t/'preview-out/previewfixture').glob('run-*/inventory.json'))
   ok(rr.returncode==0 and 'Controlled fixture landing page' in pr.read_text(),'opt-in landing-page title collected from controlled GET')
   ok('PRIVATE_BODY_SENTINEL' not in ''.join(p.read_text() for p in pr.parent.iterdir() if p.is_file()),'full preview body never exported')
   ps.write_text(ps.read_text().replace('endpoint='+base+'/\n','endpoint='+base+'/large\n'))
   rr=cli('--http-checks',scope_file=ps,policy_file=preview,output=t/'large-out')
   ok(rr.returncode==3,'oversized real HTTP response marks scan partial')
   # CT adapter fixture: no contact with the public CT provider.
   ctwork=t/'ct-unit';ctwork.mkdir()
   for file in ['records.tsv','errors.tsv','provenance.tsv','rejected.tsv']:(ctwork/file).write_text('')
   ctbody=t/'ct.json';ctbody.write_text(json.dumps([{'name_value':'new.example.test\n*.example.test\nother.invalid'}]))
   code=f'WORK={ctwork}; ROOTS=(example.test); SEEDS=(example.test); CT_ENABLED=true; request() {{ HTTP_CODE=200; HTTP_BODY={ctbody}; }}; passive_discovery'
   rr=sh(code,env);ok(rr.returncode==0 and (ctwork/'assets.txt').read_text().splitlines()==['example.test','new.example.test'],'CT names are candidates filtered by exact authorization')
   ok('certificate-transparency' in (ctwork/'provenance.tsv').read_text(),'passive discovery provenance recorded')
   ok('other.invalid' in (ctwork/'rejected.tsv').read_text(),'out-of-scope discovery candidate rejected, not probed')
   ok(sh('CT_ENABLED=true; role_scope crt.sh discovery',env).returncode==0,'CT service role explicitly enabled')
   ok(sh('CT_ENABLED=true; ROOTS=(example.test); role_scope crt.sh asset',env).returncode!=0,'provider permission does not expand asset scope')
   ok(sh('ALERT_HOSTS=(hooks.example.test); role_scope other.example.test alert',env).returncode!=0,'unapproved webhook host blocked')
   code='CLOUDS=("gcs|object|https://storage.googleapis.com/bucket/probe.txt"); role_scope storage.googleapis.com cloud https://storage.googleapis.com/bucket/other.txt'
   ok(sh(code,env).returncode!=0,'cloud authorization does not extend to neighboring objects')
   # Noncanonical XML must not manufacture a zero-object listing confirmation.
   headers.write_text('x-amz-request-id: fixture\n')
   for label,xml in [('object-attributes','<ListBucketResult><MaxKeys>0</MaxKeys><Contents xmlns="x"><Key>unexpected</Key></Contents></ListBucketResult>'),('comment-spoof','<!-- <ListBucketResult><MaxKeys>0</MaxKeys></ListBucketResult> -->')]:
    body.write_text(xml)
    rr=sh(f'HTTP_HEADERS={headers}; HTTP_BODY={body}; cloud_classify s3 bucket 200 true; echo "$CLOUD_STATUS"',env)
    ok(rr.stdout.strip()=='INDETERMINATE','noncanonical cloud XML fails closed '+label)
   # Dry-run validation includes imported data and a supplied historical state.
   badlist=t/'bad-assets.txt';badlist.write_text('bad;touch.invalid\n')
   badlist_scope=t/'badlist-scope.conf';badlist_scope.write_text(scope.read_text()+'asset_file='+str(badlist)+'\n')
   n=len(Handler.requests);rr=cli('--dry-run',scope_file=badlist_scope,output=t/'dry-invalid')
   ok(rr.returncode==2 and not (t/'dry-invalid').exists() and len(Handler.requests)==n,'dry run rejects malformed asset imports without side effects')
   rr=cli('--dry-run','--baseline',malformed,output=t/'dry-bad-baseline')
   ok(rr.returncode==2 and not (t/'dry-bad-baseline').exists(),'dry run validates supplied baseline without output creation')
   # Optional sample writing is explicitly synthetic/local, no production target output.
   if os.environ.get('SURFACEINTEL_WRITE_SAMPLES')=='1':
    dest=R/'examples/controlled-local';shutil.rmtree(dest,ignore_errors=True);dest.mkdir(parents=True)
    for path in [run,run2,failedrun]:
     shutil.copytree(path,dest/path.name)
   print(f'\nRESULT: {COUNT} passed, 0 failed')
  finally:
   http_srv.shutdown();https.shutdown();http_srv.server_close();https.server_close()

if __name__=='__main__':main()
