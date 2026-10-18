#!/usr/bin/env python3
"""WebScope: bounded linked discovery; network I/O is delegated to SurfaceIntel."""
import argparse
import collections
import fcntl
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import stat
import subprocess
import tempfile
import time
from urllib.parse import urljoin, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
VERSION = '1.0.0-rc2'
PATTERNS = json.loads((ROOT/'adapters/urlminer-patterns.json').read_text())
SENSITIVE_EXT = set(PATTERNS['SENSITIVE_EXT'].split()) | {'map', 'sqlite', 'db', 'backup'}
SENSITIVE_WORDS = PATTERNS['SENSITIVE_PATH_TOKENS'].split(',')
ACTION = re.compile(r'(^|[/_.-])(logout|signout|delete|remove|reset|unsubscribe|activate|revoke|destroy|purchase|checkout)([/_.-]|$)', re.I)
TOKEN_PATH = re.compile(r'gh[pousr]_|github_pat_|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{15,}\.', re.I)
SECRET = re.compile(r'''(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|private[_-]?key)\b["']?\s*[:=]\s*["']([^"'\r\n]{8,200})["']''')
LINK_STRING = re.compile(r'''["']((?:https?://|/|\./|\.\./)[^"'\s<>]{1,1800}|[^"'\s<>]{1,160}\.m?js(?:\?[^"'\s<>]*)?)["']''')
PUBLIC_SUFFIXES = {'co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'co.in', 'com.br', 'co.jp'}

class PolicyError(Exception):
    pass

class BudgetError(Exception):
    pass

def domain(value):
    value = value.lower().rstrip('.')
    if len(value) > 253 or value in PUBLIC_SUFFIXES or '.' not in value:
        raise PolicyError('Use a specific authorized ASCII domain, not a public suffix.')
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
        raise PolicyError('Invalid domain; use ASCII/punycode, not a URL or shell syntax.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise PolicyError('A DNS domain is required, not an IP address.')

def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()

def read_text(path, limit=1048576):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise PolicyError('Input must be a bounded regular non-symlink file.')
    value = path.read_text(encoding='utf-8')
    if any(ord(c) < 32 and c not in '\n\t' for c in value):
        raise PolicyError('Control characters are not accepted in input files.')
    return value

class Scope:
    def __init__(self, args):
        self.root = domain(args.domain)
        self.tree = args.include_subdomains
        self.excludes = [domain(x) for x in args.exclude]
        self.aliases = [domain(x) for x in args.allow_cname]
        self.cidrs = []
        for value in args.cidr:
            try:
                self.cidrs.append(str(ipaddress.ip_network(value, strict=True)))
            except ValueError as exc:
                raise PolicyError('CIDR must be canonical and network-aligned.') from exc
        if args.allow_nonpublic and not self.cidrs:
            raise PolicyError('--allow-nonpublic also requires an explicit --cidr.')
        self.nonpublic = args.allow_nonpublic
        self.ports = set(args.port or [443] + ([80] if args.allow_http else []))
        self.http = args.allow_http
        self.prefixes = args.exclude_path
        for prefix in self.prefixes:
            if not prefix.startswith('/') or not re.fullmatch(r'/[A-Za-z0-9/._~-]*', prefix) or '..' in prefix:
                raise PolicyError('Excluded path prefixes must be simple absolute paths.')
        if not self.host(self.root):
            raise PolicyError('Root domain is excluded.')

    def host(self, host):
        try:
            host = domain(host)
        except PolicyError:
            return False
        return (host == self.root or self.tree and host.endswith('.'+self.root)) and not any(host == e or host.endswith('.'+e) for e in self.excludes)

    def url(self, raw, base=None):
        if not isinstance(raw, str) or len(raw) > 2048 or re.search(r'[\x00-\x20\x7f\\]', raw):
            raise PolicyError('INVALID_URL')
        if base:
            raw = urljoin(base, raw)
        try:
            p = urlsplit(raw)
            host = p.hostname
            port = p.port or (443 if p.scheme == 'https' else 80)
        except ValueError as exc:
            raise PolicyError('INVALID_URL') from exc
        if p.scheme not in ('https', 'http') or p.scheme == 'http' and not self.http:
            raise PolicyError('SCHEME_NOT_APPROVED')
        if not host or p.username is not None or p.password is not None or not self.host(host):
            raise PolicyError('HOST_NOT_APPROVED')
        if port not in self.ports:
            raise PolicyError('PORT_NOT_APPROVED')
        path = p.path or '/'
        if not re.fullmatch(r'/[A-Za-z0-9/._~!$&()+,:;=@-]*', path) or any(x in ('.', '..') for x in path.split('/')) or '//' in path or TOKEN_PATH.search(path) or re.search(r'(?i)(token|secret|password|api[_-]?key|session(?:id)?|auth)[=:]', path):
            raise PolicyError('PATH_NOT_APPROVED')
        if any(path.startswith(x) for x in self.prefixes):
            raise PolicyError('PATH_EXCLUDED')
        netloc = domain(host) + (':'+str(port) if port != (443 if p.scheme == 'https' else 80) else '')
        return urlunsplit((p.scheme, netloc, path, '', '')), bool(p.query)

    def sensitive(self, url):
        path = urlsplit(url).path.lower()
        return Path(path).suffix.lstrip('.') in SENSITIVE_EXT or any(x in path for x in SENSITIVE_WORDS)

class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.inline = []
        self.in_script = False
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'script':
            self.in_script = True
            if a.get('src'):
                self.links.append((a['src'], 'javascript'))
        elif tag in ('a', 'iframe'):
            key = 'href' if tag == 'a' else 'src'
            if a.get(key):
                self.links.append((a[key], 'navigation'))
        elif tag == 'link' and a.get('href') and ('modulepreload' in a.get('rel', '') or a.get('as') == 'script'):
            self.links.append((a['href'], 'javascript'))
    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False
    def handle_data(self, data):
        if self.in_script:
            self.inline.append(data)

def local(args, timeout=12, input_bytes=None):
    p = subprocess.run(args, input=input_bytes, capture_output=True, timeout=timeout, env=safe_env())
    if p.returncode:
        raise PolicyError('Local adapter failed; output suppressed to avoid leaking input data.')
    if len(p.stdout) > 262144:
        raise PolicyError('Adapter output exceeded its bound.')
    return p.stdout.decode('utf-8', 'replace')

def safe_env():
    env = os.environ.copy()
    for key in ('SSLKEYLOGFILE', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'BASH_ENV', 'ENV'):
        env.pop(key, None)
    env['LC_ALL'] = 'C'
    return env

class Bridge:
    def __init__(self, scope, args, work, deadline):
        self.work, self.deadline, self.args = work, deadline, args
        scopefile, policyfile = work/'scope.conf', work/'policy.conf'
        lines = ['organization=webscope', ('domain_tree=' if scope.tree else 'host=') + scope.root]
        lines += ['exclude_tree='+x for x in scope.excludes]
        lines += ['cidr='+x for x in scope.cidrs] + ['allow_cname='+x for x in scope.aliases]
        scopefile.write_text('\n'.join(lines)+'\n')
        policy = ['config_version=1', 'timeout='+str(args.timeout), 'max_duration='+str(args.budget), 'dns_rate='+str(args.rate), 'http_rate='+str(args.rate), 'allow_nonpublic='+str(scope.nonpublic).lower(), 'ct_enabled='+str(args.ct).lower()]
        if args.ca_file:
            policy.append('ca_file='+str(Path(args.ca_file).absolute()))
        policyfile.write_text('\n'.join(policy)+'\n')
        self.p = subprocess.Popen(['bash', str(ROOT/'adapters/transport.sh'), str(scopefile), str(policyfile), str(work)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True, env=safe_env())
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.p.stdout, selectors.EVENT_READ)

    def call(self, action, value, extra=''):
        for p in self.work.iterdir():
            if p.name.startswith(('headers-', 'body-', 'code-', 'curl-', 'dns-', 'cert-', 'tls-', 'local.')) and p.is_file() and not p.is_symlink():
                p.unlink()
        if any(c in value+extra for c in '\r\n\t'):
            raise PolicyError('Invalid adapter command.')
        self.p.stdin.write((action+'\t'+value+'\t'+extra+'\n').encode())
        self.p.stdin.flush()
        end = min(self.deadline, time.monotonic() + self.args.timeout*4 + 10)
        data = b''
        while b'\n' not in data:
            remaining = end-time.monotonic()
            if remaining <= 0 or not self.sel.select(remaining):
                self.close()
                raise BudgetError('TRANSPORT_DEADLINE')
            part = os.read(self.p.stdout.fileno(), 65536)
            if not part:
                raise PolicyError('SurfaceIntel transport stopped; no network fallback is allowed.')
            data += part
            if len(data) > 262144:
                raise PolicyError('Transport result exceeded limit.')
        return json.loads(data)

    def path(self, value):
        if not value:
            return None
        p = Path(value)
        if p.parent != self.work or p.is_symlink():
            raise PolicyError('Invalid transport artifact path.')
        return p if p.is_file() else None

    def bytes(self, value):
        p = self.path(value)
        if p is None:
            return b''
        if p.stat().st_size > 131072:
            raise PolicyError('Transport artifact exceeded limit.')
        return p.read_bytes()

    def close(self):
        try:
            os.killpg(self.p.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if self.p.poll() is None:
            try:
                self.p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.p.pid, signal.SIGKILL)
                self.p.wait()
        self.sel.close()
        self.p.stdin.close()
        self.p.stdout.close()

class Engine:
    def __init__(self, args, scope, run, bridge, deadline):
        self.a, self.scope, self.run, self.bridge, self.deadline = args, scope, run, bridge, deadline
        self.urls = {}
        self.hosts = {}
        self.queue = collections.deque()
        self.scheduled = set()
        self.visited = set()
        self.errors = []
        self.rejected = collections.Counter()
        self.requests = 0
        self.dns = []
        self.tls = []
        self.headers = []
        self.secret_hints = []
        self.robots = collections.defaultdict(list)
        self.tls_origins = set()
        self.completion = 'complete_within_declared_limits'
        self.started_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    def error(self, reason):
        if reason not in self.errors:
            self.errors.append(reason)
        self.completion = 'partial'

    def budget(self):
        if time.monotonic() >= self.deadline:
            raise BudgetError('GLOBAL_DEADLINE')
        if self.requests >= self.a.max_requests:
            raise BudgetError('REQUEST_LIMIT')

    def host(self, host, source):
        try:
            host = domain(host)
        except PolicyError:
            self.rejected['INVALID_HOST'] += 1
            return False
        if not self.scope.host(host):
            self.rejected['HOST_NOT_APPROVED'] += 1
            return False
        if host not in self.hosts:
            if len(self.hosts) >= self.a.max_hosts:
                self.error('HOST_LIMIT')
                return False
            self.hosts[host] = {'host': host, 'sources': [], 'authorization': 'operator_asserted'}
            scheme = 'http' if self.a.allow_http and 443 not in self.scope.ports else 'https'
            port = min(self.scope.ports) if (443 if scheme == 'https' else 80) not in self.scope.ports else (443 if scheme == 'https' else 80)
            origin = scheme+'://'+host + (':'+str(port) if port != (443 if scheme == 'https' else 80) else '')
            for path, kind in [('/robots.txt', 'robots'), ('/sitemap.xml', 'sitemap'), ('/', 'navigation')]:
                self.add(origin+path, None, kind, 0, 'host-entry', add_host=False)
        if source not in self.hosts[host]['sources']:
            self.hosts[host]['sources'].append(source)
        return True

    def add(self, raw, base, kind, depth, source, add_host=True):
        try:
            url, query = self.scope.url(raw, base)
        except PolicyError as exc:
            self.rejected[str(exc)] += 1
            return
        host = urlsplit(url).hostname
        if add_host and not self.host(host, 'linked-host'):
            return
        if url not in self.urls:
            if len(self.urls) >= self.a.max_urls:
                self.error('URL_LIMIT')
                return
            path = urlsplit(url).path
            self.urls[url] = {'id': digest('url|'+url), 'url': url, 'kinds': [], 'sources': [], 'status': 'OBSERVED_ONLY', 'http_status': None, 'sensitive_candidate': self.scope.sensitive(url), 'query_redacted': query, 'directory_evidence': 'path-prefix only; not proof of a filesystem directory'}
        row = self.urls[url]
        if kind not in row['kinds']:
            row['kinds'].append(kind)
        # Store only canonical safe source URLs or constant source labels.
        if source not in row['sources'] and len(row['sources']) < 8:
            row['sources'].append(source)
        if query:
            row['query_redacted'] = True
            self.rejected['QUERY_NOT_FETCHED'] += 1
            return
        if ACTION.search(urlsplit(url).path):
            row['status'] = 'ACTION_PATH_NOT_REQUESTED'
            return
        if depth > self.a.depth:
            self.error('DEPTH_LIMIT')
            return
        if url not in self.scheduled:
            self.scheduled.add(url)
            self.queue.append((url, kind, depth))

    def fetch(self, url, method):
        self.budget()
        # Repeat name/path validation immediately before each bridge call.
        normalized, query = self.scope.url(url)
        if normalized != url or query:
            raise PolicyError('Request normalization mismatch.')
        if method == 'GET' and self.scope.sensitive(url):
            # robots/sitemap are the only explicit non-HTML discovery documents.
            if urlsplit(url).path not in ('/robots.txt', '/sitemap.xml'):
                raise PolicyError('Sensitive candidate bodies are never requested.')
        self.requests += 1
        reply = self.bridge.call(method, url)
        if reply.get('reason') != 'RESPONSE_RECEIVED':
            self.error('REQUEST_FAILED:'+reply.get('reason', 'UNKNOWN'))
            return reply, {}, b''
        header_path = self.bridge.path(reply['headers'])
        normalized_headers = local(['awk', '-f', str(ROOT/'adapters/headerguard.awk'), str(header_path)]) if header_path else ''
        headers = {}
        cookie_flags = []
        for line in normalized_headers.splitlines():
            fields = line.split('\t', 2)
            if fields[0] == 'HDR' and len(fields) == 3:
                headers[fields[1].lower()] = fields[2]
            elif fields[0] == 'COOKIE' and len(fields) >= 2:
                attrs = fields[1].lower().split(';')[1:]
                cookie_flags.append({'secure': any(x.strip() == 'secure' for x in attrs), 'httponly': any(x.strip() == 'httponly' for x in attrs), 'samesite_present': any(x.strip().startswith('samesite=') for x in attrs)})
        if method == 'HEAD':
            checks = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy']
            self.headers.append({'url': url, 'method': 'HEAD', 'header_presence': {x: x in headers for x in checks}, 'cookie_flags': cookie_flags, 'cors_probe': 'NOT_RUN', 'interpretation': 'Presence only; not a security grade or policy correctness verdict.'})
        body = self.bridge.bytes(reply.get('body')) if method == 'GET' else b''
        return reply, headers, body

    def secret_scan(self, text, url):
        for m in SECRET.finditer(text):
            value = m.group(2)
            if value.lower() in ('changeme', 'your_api_key', 'undefined', 'placeholder'):
                continue
            entry = {'url': url, 'label': m.group(1).lower(), 'value': '[REDACTED]', 'confidence': 'LOW', 'status': 'POTENTIAL_LITERAL_NOT_VALIDATED'}
            if entry not in self.secret_hints:
                self.secret_hints.append(entry)
        # No hashing of low-entropy secret values, no credential validity testing.

    def javascript(self, text, url, depth):
        self.secret_scan(text, url)
        matches = list(LINK_STRING.finditer(text))
        if len(matches) > 500:
            self.error('JS_REFERENCE_LIMIT')
        for m in matches[:500]:
            candidate = m.group(1)
            kind = 'javascript' if re.search(r'\.m?js(?:\?|$)', candidate) else 'route_hint'
            self.add(candidate, url, kind, depth+1, url)
        for match in re.finditer(r'(?m)^\s*//[#@]\s*sourceMappingURL=(\S+)', text):
            self.add(match.group(1), url, 'source_map_metadata', depth+1, url)

    def parse(self, url, kind, depth, content_type, body):
        text = body.decode('utf-8', 'replace')
        if kind == 'robots':
            origin = self.origin(url)
            for line in text.splitlines()[:2000]:
                key, sep, value = line.partition(':')
                value = value.strip()
                if sep and key.lower() == 'disallow' and (value.startswith('/') or value == '*'):
                    # Conservatively union all groups; never fetch these paths.
                    prefix = value.split('*', 1)[0].rstrip('$') or '/'
                    self.robots[origin].append(prefix)
                    self.add(prefix, url, 'robots_disallow_observation', depth+1, url)
                elif sep and key.lower() == 'sitemap':
                    self.add(value, url, 'sitemap', depth+1, url)
        elif kind == 'sitemap':
            if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
                self.error('UNSUPPORTED_SITEMAP_XML')
                return
            try:
                tree = ET.fromstring(text)
                if tree.tag.rsplit('}', 1)[-1] not in ('urlset', 'sitemapindex'):
                    raise ValueError('not sitemap')
                child_kind = 'sitemap' if tree.tag.rsplit('}', 1)[-1] == 'sitemapindex' else 'navigation'
                for elem in tree.iter():
                    if elem.tag.rsplit('}', 1)[-1] == 'loc' and elem.text:
                        self.add(elem.text.strip(), url, child_kind, depth+1, url)
            except (ET.ParseError, ValueError):
                self.error('INVALID_SITEMAP_XML')
        elif kind == 'javascript' or content_type in ('application/javascript', 'text/javascript', 'application/x-javascript'):
            self.javascript(text, url, depth)
        elif content_type in ('text/html', 'application/xhtml+xml'):
            parser = Links()
            parser.feed(text)
            for candidate, candidate_kind in parser.links:
                self.add(candidate, url, candidate_kind, depth+1, url)
            for inline in parser.inline:
                self.javascript(inline, url, depth)

    @staticmethod
    def origin(url):
        p = urlsplit(url)
        return p.scheme+'://'+p.netloc

    def tls_check(self, url):
        origin = self.origin(url)
        if not url.startswith('https:') or origin in self.tls_origins:
            return
        self.tls_origins.add(origin)
        self.budget()
        self.requests += 1
        reply = self.bridge.call('TLS', origin+'/')
        records = self.bridge.bytes(reply.get('records')).decode('utf-8', 'replace')
        for line in records.splitlines():
            fields = line.split('\t')
            if len(fields) == 9:
                self.tls.append({'origin': origin, 'kind': fields[0], 'status': fields[3], 'severity': fields[5], 'evidence': fields[8], 'engine': 'SurfaceIntel'})
        if self.bridge.bytes(reply.get('errors')):
            self.error('TLS_COLLECTION_INCOMPLETE')
        cert = self.bridge.path(reply.get('certificate'))
        if cert and cert.stat().st_size:
            target = urlsplit(url)
            local(['bash', str(ROOT/'adapters/tlswatch-local.sh'), target.hostname, str(target.port or 443), str(cert), str(self.bridge.work)])
            findings = self.bridge.work/'local.find'
            if findings.exists():
                for line in findings.read_text().splitlines():
                    fields = line.split('|', 3)
                    if len(fields) == 4:
                        self.tls.append({'origin': origin, 'status': fields[0], 'check': fields[2], 'engine': 'TLSWatch-local-certificate', 'interpretation': 'Local leaf-certificate check; not protocol/cipher enumeration or a separate chain verdict.'})
                findings.unlink()

    def discover(self):
        self.host(self.scope.root, 'configured-root')
        for file in self.a.import_hosts:
            self.budget()
            text = read_text(file)
            values = []
            lines = text.splitlines()
            if len(lines) > 10000:
                self.error('IMPORT_LINE_LIMIT')
            for line in lines[:10000]:
                if not line or line.startswith('#'):
                    continue
                try:
                    values.append(domain(line))
                except PolicyError:
                    self.rejected['INVALID_IMPORTED_HOST'] += 1
            if values:
                # Existing ReconScope normalization helper, with glob expansion disabled.
                normalized = local(['bash', str(ROOT/'adapters/reconscope-local.sh')], input_bytes=','.join(values[:1000]).encode())
                for host in normalized.split(','):
                    self.host(host, 'ReconScope-compatible-import')
            if len(values) > 1000:
                self.error('IMPORT_LIMIT')
        if self.a.ct:
            self.budget()
            self.requests += 1
            reply = self.bridge.call('CT', self.scope.root)
            try:
                if reply.get('status') != '200' or reply.get('reason') != 'RESPONSE_RECEIVED':
                    raise ValueError('provider unavailable')
                rows = json.loads(self.bridge.bytes(reply.get('body')))
                if not isinstance(rows, list) or not all(isinstance(r, dict) and isinstance(r.get('name_value'), str) for r in rows):
                    raise ValueError('provider shape')
                for row in rows[:1000]:
                    for name in row['name_value'].splitlines()[:100]:
                        if name.startswith('*.'):
                            self.rejected['WILDCARD_NOT_EXPANDED'] += 1
                        else:
                            self.host(name.lower(), 'certificate-transparency')
                if len(rows) > 1000:
                    self.error('CT_ROW_LIMIT')
            except (ValueError, TypeError):
                self.error('CT_UNAVAILABLE_OR_BOUNDED')
        while self.queue:
            self.budget()
            url, kind, depth = self.queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)
            row = self.urls[url]
            if any(urlsplit(url).path.startswith(p) for p in self.robots[self.origin(url)]):
                row['status'] = 'ROBOTS_DISALLOWED_NOT_REQUESTED'
                continue
            self.tls_check(url)
            reply, headers, _ = self.fetch(url, 'HEAD')
            row['http_status'] = int(reply.get('status', '000'))
            row['status'] = reply.get('reason', 'UNKNOWN')
            if row['status'] != 'RESPONSE_RECEIVED':
                continue
            code = row['http_status']
            if 300 <= code < 400:
                if headers.get('location'):
                    self.add(headers['location'], url, kind, depth+1, url)
                continue
            discovery_document = (kind == 'robots' and urlsplit(url).path == '/robots.txt') or (kind == 'sitemap' and urlsplit(url).path == '/sitemap.xml')
            if row['sensitive_candidate'] and not discovery_document:
                row['status'] = 'METADATA_ONLY_REVIEW_REQUIRED' if 200 <= code < 300 else ('ACCESS_DENIED' if code == 403 else 'AUTH_REQUIRED' if code == 401 else 'HTTP_METADATA_OBSERVED')
                continue
            if code != 200 or kind == 'route_hint':
                continue
            ctype = headers.get('content-type', '').split(';', 1)[0].lower()
            allowed = {'text/html', 'application/xhtml+xml'}
            if kind == 'javascript':
                allowed |= {'text/javascript', 'application/javascript', 'application/x-javascript'}
            if kind == 'robots':
                allowed = {'text/plain'}
            if kind == 'sitemap':
                allowed = {'application/xml', 'text/xml'}
            if ctype not in allowed:
                row['status'] = 'BODY_NOT_REQUESTED_UNAPPROVED_TYPE'
                continue
            reply, get_headers, body = self.fetch(url, 'GET')
            if reply.get('reason') != 'RESPONSE_RECEIVED' or reply.get('status') != '200':
                row['status'] = 'GET_INCOMPLETE'
                self.error('GET_INCOMPLETE')
                continue
            actual_type = get_headers.get('content-type', '').split(';', 1)[0].lower()
            if actual_type not in allowed:
                row['status'] = 'GET_TYPE_CHANGED_DISCARDED'
                self.error('GET_TYPE_CHANGED')
                continue
            row['body_sha256'] = digest(body)
            row['body_bytes'] = len(body)
            row['status'] = 'BOUNDED_PUBLIC_DOCUMENT_PARSED'
            self.parse(url, kind, depth, actual_type, body)
        for host in sorted(self.hosts):
            for record_type in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'):
                if time.monotonic() >= self.deadline:
                    raise BudgetError('GLOBAL_DEADLINE')
                reply = self.bridge.call('DNS', host, record_type)
                row = {'host': host, 'type': record_type, **reply}
                if record_type == 'CNAME':
                    row['provider_hints'] = [local(['bash', str(ROOT/'adapters/dnsshield-local.sh'), name]) for name in reply.get('values', '').splitlines()[:20]]
                self.dns.append(row)
                if reply.get('status') not in ('ANSWER', 'NODATA', 'NXDOMAIN'):
                    self.error('DNS_INCOMPLETE')

    def report(self):
        dirs = set()
        for url in self.urls:
            p = urlsplit(url)
            parts = p.path.split('/')[:-1]
            for i in range(1, len(parts)+1):
                dirs.add(self.origin(url)+'/'.join(parts[:i])+'/')
        urls = sorted(self.urls.values(), key=lambda r: r['url'])
        scope_record = {'domain': self.scope.root, 'include_subdomains': self.scope.tree, 'excluded_trees': self.scope.excludes, 'excluded_paths': self.scope.prefixes, 'approved_cnames': self.scope.aliases, 'cidrs': self.scope.cidrs, 'allow_nonpublic': self.scope.nonpublic, 'allow_http': self.scope.http, 'ports': sorted(self.scope.ports), 'ca_bundle_sha256': self.a.ca_sha256}
        report = {'run_id': self.run.name, 'started_at': self.started_at, 'finished_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'scope': scope_record, 'scope_sha256': digest(json.dumps(scope_record, sort_keys=True)), 'schema_version': '1', 'tool': 'WebScope', 'version': VERSION, 'domain': self.scope.root, 'completion': self.completion, 'coverage': {'exhaustive': False, 'subdomain_tree_authorized': self.scope.tree, 'external_ct_enabled': self.a.ct, 'wordlist_discovery': False, 'raw_bodies_saved': False, 'secret_file_body_requests': False, 'query_urls_requested': False, 'js_execution': False, 'directory_semantics': 'Inferred URL prefixes, not filesystem enumeration', 'request_count': self.requests, 'dns_requests_additional': True}, 'hosts': list(self.hosts.values()), 'urls': urls, 'directory_prefixes': sorted(dirs), 'dns': self.dns, 'tls': self.tls, 'headers': self.headers, 'potential_js_literals': self.secret_hints, 'rejected_counts': dict(self.rejected), 'errors': self.errors, 'limits': {k: getattr(self.a, k) for k in ('max_hosts', 'max_urls', 'max_requests', 'depth', 'budget', 'timeout', 'rate')}, 'integrations': {'ReconScope': 'Local host-list normalization/import compatibility', 'URLMiner': 'Reused URL classification patterns; no archive crawler launch', 'HeaderGuard': 'Original offline header normalizer; presence/cookie-flag observations', 'DNSShield': 'Original offline CNAME provider classifier; no AXFR or selector guessing', 'TLSWatch': 'Original local certificate checks; no protocol/cipher sweep', 'SurfaceIntel': 'Active scope/DNS/IP pinning, DNS inventory, CT transport and TLS lifecycle'}}
        (self.run/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        outputs = {'subdomains.txt': sorted(self.hosts), 'all_urls.txt': [r['url'] for r in urls], 'directories.txt': sorted(dirs), 'js_files.txt': [r['url'] for r in urls if 'javascript' in r['kinds'] or urlsplit(r['url']).path.endswith(('.js', '.mjs'))], 'sensitive_candidates.txt': [r['url'] for r in urls if r['sensitive_candidate']], 'route_hints.txt': [r['url'] for r in urls if 'route_hint' in r['kinds']]}
        for name, lines in outputs.items():
            (self.run/name).write_text('\n'.join(lines)+ ('\n' if lines else ''))
        summary = f'WebScope {VERSION}\nDomain: {self.scope.root}\nCompletion: {self.completion}\nHosts: {len(self.hosts)} | URLs: {len(urls)} | HTTP/TLS/provider operations: {self.requests}\nJavaScript URLs: {len(outputs["js_files.txt"])} | Sensitive-path candidates: {len(outputs["sensitive_candidates.txt"])}\nNo completeness, directory existence, credential validity or sensitive-content exposure claim.\nErrors/limits: {", ".join(self.errors) or "none recorded"}\n'
        (self.run/'summary.txt').write_text(summary)
        rows = ''.join('<tr><td>'+html.escape(r['url'])+'</td><td>'+html.escape(r['status'])+'</td></tr>' for r in urls)
        (self.run/'report.html').write_text('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>WebScope report</title><style>body{font:16px system-ui;background:#0b1220;color:#dbeafe;margin:40px}pre{white-space:pre-wrap}table{border-collapse:collapse;width:100%}td{padding:10px;border-bottom:1px solid #334155;overflow-wrap:anywhere}h1{color:#67e8f9}</style><h1>WebScope · authorized linked discovery</h1><pre>'+html.escape(summary)+'</pre><table><tr><th>Observed URL</th><th>Evidence state</th></tr>'+rows+'</table>')
        return report

def parser():
    p = argparse.ArgumentParser(description='WebScope: explicitly authorized, bounded linked web discovery; no wordlists or private-file downloads.')
    p.add_argument('domain', help='Domain only, e.g. example.invalid')
    p.add_argument('--version', action='version', version='WebScope '+VERSION)
    for flag in ('authorized', 'dry-run', 'include-subdomains', 'ct', 'allow-http', 'allow-nonpublic'):
        p.add_argument('--'+flag, action='store_true')
    for flag in ('exclude', 'exclude-path', 'allow-cname', 'cidr', 'import-hosts'):
        p.add_argument('--'+flag, action='append', default=[])
    p.add_argument('--port', action='append', type=int)
    p.add_argument('--ca-file')
    p.add_argument('--output', default='./webscope-reports')
    for flag, default in [('max-hosts', 32), ('max-urls', 200), ('max-requests', 400), ('depth', 3), ('budget', 600), ('timeout', 6), ('rate', 2)]:
        p.add_argument('--'+flag, type=int, default=default)
    return p

def validate(args):
    scope = Scope(args)
    for key in ('exclude', 'exclude_path', 'allow_cname', 'cidr'):
        if len(getattr(args, key)) > 256:
            raise PolicyError('Too many scope entries.')
    if len(args.import_hosts) > 16 or len(args.port or []) > 16:
        raise PolicyError('Too many import files or ports.')
    bounds = {'max_hosts': (1, 128), 'max_urls': (1, 2000), 'max_requests': (1, 4000), 'depth': (0, 8), 'budget': (10, 3600), 'timeout': (1, 30), 'rate': (1, 10)}
    for key, (low, high) in bounds.items():
        if not low <= getattr(args, key) <= high:
            raise PolicyError(key+' outside supported bounds.')
    if any(not 1 <= x <= 65535 for x in scope.ports):
        raise PolicyError('Invalid port.')
    if args.ct and not args.include_subdomains:
        raise PolicyError('--ct requires explicit --include-subdomains authorization.')
    for p in args.import_hosts:
        read_text(p)
    args.ca_sha256 = 'system-trust-store-not-hashed'
    if args.ca_file:
        if any(c in str(Path(args.ca_file).absolute()) for c in '\n\t\r'):
            raise PolicyError('Invalid CA file path.')
        ca = read_text(args.ca_file)
        if 'PRIVATE KEY' in ca or '-----BEGIN CERTIFICATE-----' not in ca:
            raise PolicyError('CA input must be a public certificate bundle, not a private key.')
        args.ca_sha256 = digest(Path(args.ca_file).read_bytes())
    return scope

def private_output(value):
    path = Path(value).absolute()
    for p in [path]+list(path.parents):
        if p.is_symlink():
            raise PolicyError('Output paths must not traverse symlinks.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = path.stat()
    if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) & 0o077:
        raise PolicyError('Existing output root must be owned by this user with mode 0700.')
    return path

def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    bridge, lock, engine = None, None, None
    termination_code = 130
    try:
        scope = validate(args)
        if args.dry_run:
            print(json.dumps({'domain': scope.root, 'tree': scope.tree, 'ct': args.ct, 'ports': sorted(scope.ports), 'network_requests': 0, 'output_created': False, 'status': 'VALIDATED_PLAN'}))
            return 0
        if not args.authorized:
            raise PolicyError('Add --authorized only when you own the assets or have written permission; use --dry-run otherwise.')
        for command in ('curl', 'dig', 'awk', 'sha256sum', 'date', 'stat', 'sort', 'sed', 'grep', 'cut', 'diff', 'cmp', 'tr', 'mktemp', 'find', 'head', 'tail', 'wc'):
            if not shutil.which(command):
                raise PolicyError('Missing runtime dependency: '+command+' (nothing installed).')
        output = private_output(args.output)
        lock = os.open(output/'.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        if os.fstat(lock).st_uid != os.getuid() or os.fstat(lock).st_mode & 0o077:
            raise PolicyError('Unsafe lock file.')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('WebScope: another run holds this output lock.', file=__import__('sys').stderr)
            return 75
        run = Path(tempfile.mkdtemp(prefix='run-'+time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())+'-', dir=output))
        (run/'INCOMPLETE').write_text('Report finalization has not completed. Do not treat this directory as a finished audit.\n')
        deadline = time.monotonic()+args.budget
        def interrupt(_sig, _frame):
            nonlocal termination_code
            termination_code = 128+_sig
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, interrupt)
        with tempfile.TemporaryDirectory(prefix='.work-', dir=run) as tmp:
            bridge = Bridge(scope, args, Path(tmp), deadline)
            engine = Engine(args, scope, run, bridge, deadline)
            try:
                engine.discover()
            except BudgetError as exc:
                engine.error(str(exc))
            except KeyboardInterrupt:
                engine.error('INTERRUPTED')
            except (PolicyError, OSError, ValueError, subprocess.SubprocessError):
                engine.error('ADAPTER_OR_COLLECTION_ERROR')
            finally:
                bridge.close()
                bridge = None
            engine.report()
            (run/'INCOMPLETE').unlink()
        print(str(run))
        return termination_code if 'INTERRUPTED' in engine.errors else 3 if engine.completion == 'partial' else 0
    except KeyboardInterrupt:
        return termination_code
    except (PolicyError, OSError, ValueError) as exc:
        # Do not echo attacker-controlled values or OS exception paths.
        print('WebScope: configuration/output error. '+(str(exc) if isinstance(exc, PolicyError) else 'Review input files and filesystem permissions.'), file=__import__('sys').stderr)
        return 2
    finally:
        if bridge:
            bridge.close()
        if lock is not None:
            os.close(lock)

if __name__ == '__main__':
    raise SystemExit(main())
