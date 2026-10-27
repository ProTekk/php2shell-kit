#!/usr/bin/env python3
"""selftest.py — the kit proves itself on THIS box before you trust its
verdicts. One command, local-only by design: no venue, no network, no PHP
assumed beyond what's on PATH — it must pass in a tarball on a stranger's
machine (contract #8: environment-agnostic by construction).

Cells: dispatcher smokes · tier-script help · CLI detect matrix against every
php discovered (exit-code contract asserted against known verdicts) · the
vendor 618 arm discriminator · portability (no PHP2SHELL_PROJ, foreign cwd).

  python3 selftest.py            full (arms spin a local php -S per build)
  python3 selftest.py --fast     skip the OOM arms (help + CLI matrix only)

Exit 0 = every cell PASS. Exit 1 = at least one FAIL (printed in red).
"""
import glob, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY, KIT = sys.executable, os.path.join(ROOT, 'kit')
DETECT = os.path.join(ROOT, 'detect', 'detect.py')
CVE    = os.path.join(ROOT, 'prove',  'cve_shape.py')

# The kit's own matrix facts (re-proven 2026-10-26, tonight's receipts):
# detect exit codes on known builds. Unknown versions accept any clean 0/2/3.
EXPECT = {'8.3.6': 2, '8.3.36': 0, '8.5.12': 0}

def color_on():
    return (sys.stdout.isatty() and not os.environ.get('NO_COLOR')
            and os.environ.get('TERM') != 'dumb')
C = color_on()
def paint(code, s): return ('\033[%sm%s\033[0m' % (code, s)) if C else s
def head(s): return paint('1;36', s)
def step(i, n, s): return (paint('36', '▸') + ' ' + paint('2', '[%d/%d]' % (i, n))
                           + ' ' + paint('1', s))
def ok():  return paint('1;32', 'PASS')
def bad(): return paint('1;31', 'FAIL')

ROWS = []
def cell(name, detail, passed):
    ROWS.append(bool(passed))
    print('  %s  %s %s' % (ok() if passed else bad(),
                           name.ljust(38), paint('2', detail)))

def run(args, env=None, timeout=180, cwd=None, clean_env=False):
    e = dict(os.environ)
    if clean_env: e.pop('PHP2SHELL_PROJ', None)
    e.update(env or {})
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, env=e, cwd=cwd).returncode
    except Exception:
        return 99

def php_ver(b):
    try:
        return subprocess.run([b, '-r', 'echo PHP_VERSION;'],
                              capture_output=True, text=True,
                              timeout=15).stdout.strip()
    except Exception:
        return '?'

def find_phps():
    cands = []
    for pat in ('/usr/bin/php[0-9.]*', '/usr/local/bin/php[0-9.]*',
                '/usr/bin/php', '/usr/local/bin/php'):
        cands += glob.glob(pat)
    proj = os.environ.get('PHP2SHELL_PROJ')
    if proj:
        cands += sorted(glob.glob(os.path.join(proj, 'php-*/sapi/cli/php')))
    out, seen = [], set()
    for p in cands:
        rp = os.path.realpath(p)
        if os.path.isfile(rp) and os.access(rp, os.X_OK) and rp not in seen:
            seen.add(rp); out.append(p)
    return sorted(out)

def main():
    fast = '--fast' in sys.argv
    phps = find_phps()
    n = 5 - (1 if fast else 0)
    print(head('┌ selftest · kit regression harness — local, network-free'))

    print('  ' + step(1, n, 'dispatcher smokes'))
    cell('kit help', 'rc 0', run([PY, KIT]) == 0)
    cell('kit targets', 'rc 0', run([PY, KIT, 'targets']) == 0)
    cell('kit versions', 'rc 0', run([PY, KIT, 'versions']) == 0)

    print('  ' + step(2, n, 'tier help — argparse on every script that speaks it'))
    for s in ('detect/detect.py', 'prove/cve_shape.py', 'exploit/uaf.py',
              'exploit/pubstate.py', 'exploit/php2shell.py'):
        cell('help ' + s, 'rc 0', run([PY, os.path.join(ROOT, s), '-h']) == 0)

    print('  ' + step(3, n, 'CLI detect matrix — exit-code contract on every php found (%d)' % len(phps)))
    if not phps:
        cell('php discovery', 'no php on PATH — install php, or set PHP2SHELL_PROJ', False)
    for b in phps:
        v = php_ver(b)
        rc = run([PY, DETECT, '--php-bin', b, '--nocolor'], timeout=60)
        want = EXPECT.get(v)
        good = rc in (0, 2, 3) and (want is None or rc == want)
        cell('detect ' + b, 'v=%-7s rc=%d%s' % (
            v, rc, '' if want is None else ' (matrix wants %d)' % want), good)

    step_no = 4
    if not fast:
        print('  ' + step(step_no, n, 'vendor 618 arm — behavioral discriminator (spins a local php -S per build)'))
        for b in phps:
            v = php_ver(b)
            want = EXPECT.get(v)
            rc = run([PY, CVE, 'stock618'], env={'PHP_BIN': b}, timeout=240)
            good = rc in (0, 2) and (want is None or rc == want)
            cell('arm stock618 ' + b, 'v=%-7s rc=%d%s' % (
                v, rc, '' if want is None else ' (matrix wants %d)' % want), good)
        step_no += 1

    print('  ' + step(step_no, n, 'portability — no PHP2SHELL_PROJ, foreign cwd (tarball contract)'))
    import tempfile
    foreign = tempfile.mkdtemp(prefix='php2shell-selftest-')
    cell('kit help from %s/…' % os.path.basename(foreign),
         'rc 0', run([PY, KIT], cwd=foreign, clean_env=True) == 0)
    cell('kit versions (PHP2SHELL_PROJ unset)',
         'rc 0', run([PY, KIT, 'versions'], clean_env=True) == 0)

    total, passed = len(ROWS), sum(ROWS)
    print('\n' + head('└ selftest · %d/%d cells ' % (passed, total))
          + (ok() if passed == total else bad()))
    if passed != total:
        print('  ' + paint('1;33', 'FAIL cells above — fix before trusting this box\'s verdicts'))
    return 0 if passed == total else 1

if __name__ == '__main__':
    sys.exit(main())
