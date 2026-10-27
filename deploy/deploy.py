#!/usr/bin/env python3
"""deploy.py — the venue trio: what every live target needs in its docroot
before the sweep and the exploits can run there.

  php2shell_detect.php   the sweep detector (lanes A/C/D)
  app.php                staleness lane read-back + exploit dial-back host
  cve2_app.php           chain-gate app (CVE2-OK responder)

  kit deploy --check host:port                      presence only, no writes
  kit deploy --docker NAME [--docroot /var/www/html]  docker cp the trio
  kit deploy --scp user@host:/path                   scp the trio

STALE COPY is a real verdict: a 200 without the marker means an older deploy
is serving that path (the kit's own field set moves — redeploy). Exit 0 all
good · 2 partial · 4 bad usage. stdlib python3; docker/scp are PATH tools.
"""
import argparse, os, shutil, subprocess, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRIO = [('detect/php2shell_detect.php', 'php2shell_detect.php', 'PHP2SHELL_DETECT|'),
        ('bench/app.php',               'app.php',              'PLANTED='),
        ('bench/apps/cve2_app.php',     'cve2_app.php',         'CVE2-OK')]

def color_on():
    return (sys.stdout.isatty() and not os.environ.get('NO_COLOR')
            and os.environ.get('TERM') != 'dumb')
C = color_on()
def paint(code, s): return ('\033[%sm%s\033[0m' % (code, s)) if C else s
def step(i, n, s): return (paint('36', '▸') + ' ' + paint('2', '[%d/%d]' % (i, n))
                           + ' ' + paint('1', s))
def tag(t, col): return paint(col, '[ %s ]' % t)
OK, MISS, STALE, DIM, DIMc = '1;32', '1;31', '1;33', '2', '2'

def fetch(base, dest, timeout=10):
    url = base.rstrip('/') + '/' + dest
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read(4096).decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, ''
    except Exception:
        return 0, ''

def check(base):
    print('  ' + paint(DIM, 'venue docroot: %s' % base.rstrip('/')))
    rc = 0
    for i, (src, dest, marker) in enumerate(TRIO, 1):
        status, body = fetch(base, dest)
        if status == 200 and marker in body:
            print('  %s %s %s' % (step(i, 3, dest.ljust(22)),
                                  tag('PRESENT', OK), paint(DIM, 'marker %s' % marker)))
        elif status == 200:
            print('  %s %s %s' % (step(i, 3, dest.ljust(22)),
                                  tag('STALE COPY', STALE),
                                  paint(DIM, '200 but no %s — redeploy' % marker)))
            rc = 2
        else:
            print('  %s %s %s' % (step(i, 3, dest.ljust(22)),
                                  tag('MISSING', MISS),
                                  paint(DIM, 'HTTP %s' % (status or 'unreachable'))))
            rc = 2
    return rc

def sh(argv, timeout=30):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

def push(mode, argv_for, verify_for=None):
    bin_needed = {'docker': 'docker', 'scp': 'scp'}[mode]
    if not shutil.which(bin_needed):
        print('  ' + paint('1;31', '✗ %s not on PATH' % bin_needed)); return 4
    rc = 0
    for i, (src, dest, _marker) in enumerate(TRIO, 1):
        path = os.path.join(ROOT, src)
        code, out = sh(argv_for(path, dest))
        if code == 0:
            line = paint(DIM, out.splitlines()[-1] if out else 'copied')
        else:
            line = paint('1;31', (out.splitlines() or ['failed'])[-1][:70])
            rc = 2
        print('  %s %s %s' % (step(i, 3, dest.ljust(22)),
                              tag('COPIED', OK) if code == 0 else tag('FAILED', MISS),
                              line))
    if verify_for:
        code, out = sh(verify_for())
        if code != 0:
            print('  ' + paint('1;31', 'verify: %s' % out[:90])); rc = 2
        else:
            print('  ' + paint(DIM, 'verify: ' + out.replace('\n', ' · ')[:90]))
    return rc

def main():
    ap = argparse.ArgumentParser(description='deploy the venue trio')
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--check', metavar='host:port',
                   help='HTTP presence of the trio (no writes)')
    g.add_argument('--docker', metavar='CONTAINER', help='docker cp the trio into the container')
    g.add_argument('--scp', metavar='user@host:/path', help='scp the trio')
    ap.add_argument('--docroot', default='/var/www/html',
                    help='container docroot (default /var/www/html; docker mode only)')
    a = ap.parse_args()

    if a.check:
        h, _, p = a.check.partition(':')
        base = 'http://%s:%s' % (h, p or '80')
        print('\n' + paint('1;36', '┌ deploy · check') + ' ' + paint('1', base))
        sys.exit(check(base))
    if a.docker:
        print('\n' + paint('1;36', '┌ deploy · docker cp →') + ' '
              + paint('1', '%s:%s' % (a.docker, a.docroot)))
        sys.exit(push('docker',
                      lambda p, d: ['docker', 'cp', p, '%s:%s/%s' % (a.docker, a.docroot, d)],
                      verify_for=lambda: ['docker', 'exec', a.docker, 'sh', '-c',
                                          'ls %s/%s %s/app.php %s/cve2_app.php'
                                          % (a.docroot, 'php2shell_detect.php', a.docroot, a.docroot)]))
    # scp
    print('\n' + paint('1;36', '┌ deploy · scp →') + ' ' + paint('1', a.scp))
    dest = a.scp if a.scp.endswith('/') else a.scp + '/'
    sys.exit(push('scp', lambda p, d: ['scp', '-q', '-o', 'BatchMode=yes', '-o',
                                       'ConnectTimeout=10', p, dest + d]))

if __name__ == '__main__':
    sys.exit(main())
