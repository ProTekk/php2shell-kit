# php2shell-kit

An all-in-one testing + exploit kit for the PHP `session.upload_progress`
attack surface — the **PHP2Shell** pair (CVE-2026-109618/619) *and* an
uncatalogued exploitation lever that the vendor fixes never touched.

One `python3` dispatcher, zero dependencies, exit code = verdict. From
"is this box affected?" to "I have a shell on it" in one command.

```console
$ ./kit selftest                                    # the kit proves itself on this box
$ ./kit triage --url http://192.0.2.10:18990/       # or point it at a target
```

## What this is

PHP's upload-progress feature (`session.upload_progress.enabled=1` — the
default) writes into `$_SESSION` before your application code runs. In
October 2026 the PHP project shipped emergency fixes for two
request-lifetime bugs in that path (**PHP2Shell**): a silent
OOM-next-request bailout and stale-globals corruption.

This kit detects both — **and** carries a second, independent finding:
a **frozen-counter staleness** in the same feature (the progress entry
hands back a cached `post_bytes_processed` read through a dangling
bucket pointer). That lever:

- was never a vendor CVE, so it was never patched —
  it walks through the 8.3.36 fix and fires identically on 8.5.12,
  PHP's latest-stable era;
- is **per-box deterministic** — the frozen-counter signature on this
  lab's 8.3.36 harness is byte-identical run-to-run and 8.3.6→8.5.12
  (`205,335 / 517,337`), verified 5/5;
- has two working lever regimes — a **staleness chain** (harness /
  `cleanup=0` configs) and a **pubstate lever** that fires on pure
  vendor-default config (`cleanup=1`, zero ini), proven 3/3 on stock
  prefork, FPM, and mod_php venues.

So the sweep answers two different questions, always in the same pass —
because running only the vendor lane creates a false impression that
nothing is exploitable:

> **A closed vendor CVE pair ≠ safe.** The staleness lane rides every
> sweep, and patched venues print the companion line.

Adjacent note: **CVE-2026-115560** (serializer-mismatch, advisory-only,
unpatched) is a *third* bug in the same feature. Same street, different
house — this kit's staleness lane is not that lane, but the sweep
carries its **config gate** anyway: `serialize_handler` swapped away
from `php` is greppable without an exploit, so every verdict box can
answer "is this box even armed for 115560?" (`ser=` field; the gate
never moves the exit code — it's advisory).

## What it does

```
kit triage   --php-bin B | --url U     full ladder -> colored one-page summary
kit detect   --php-bin B | --url U     one sweep: vendor pair + staleness + lever + 115560 gate
kit prove    staleness --target ip:port      frozen-counter signature, live venue
kit prove    cve618|cve619 [--php-bin B]     vendor regression-shape arm (local build)
kit prove    arm --target ip:port            vendor discriminator, live venue (loud: forces an OOM)
kit exploit  staleness host[:port]           UAF chain -> pty shell over connect-back
kit exploit  pubstate  host[:port]           stock-config lever shell (works on patched venues)
kit exploit  aio|--wp ...                    AIO cells · consumer-app census
kit bench    serve [mode]                    local setarch -R php -S harness
kit deploy   --check H:P | --docker C | --scp u@h:/p   docroot trio: presence / push
kit selftest [--fast]                        the kit proves itself on this box (no network)
kit targets [--json] | kit versions          venue notes (author's map, when present) · php builds found on this box
```

- **Exit code IS the verdict**: `0` clean/patched · `2` vulnerable ·
  `3` no-trigger/not-applicable. Scriptable in audit passes.
- **The kit proves itself**: `kit selftest` runs 16 cells — dispatcher
  smokes, tier help, the CLI detect matrix against known verdicts on
  every PHP build it can find, the vendor arms, and a tarball-
  portability cell (no project tree, foreign cwd) — no network, ~90 s.
  Run it on a fresh clone before trusting a verdict on a stranger's box.
- **Detect** works on CLI boxes (`--php-bin`) and live web venues
  (`--url`). A bare `http://host:port/` auto-finds the deployed
  detector. Probe beats lineage: distro backports can lie about
  version floors, so the behavioral probe always overrides.
- **Exploit dial-back** proves code execution by phoning *you* back
  from the target — the identity triple (`user / hostname`) is minted
  on the target, and lands as the web daemon's identity on web venues.
- **Safety**: the triage/detect lanes are benign by design (R1/R2/R3,
  dial-back to a refused port, no OOM, no log spam). The `prove arm`
  discriminator deliberately forces an OOM and can stall a
  single-worker venue for minutes mid-arm — don't fire it at
  production without saying so.
- **Honest scope on the RCE leg**: payload execution is app-code
  `system()` *gated by* the observed UAF/staleness signature — PHP
  being vulnerable is necessary, not sufficient; the application must
  actually read the corrupted entry.

## Receipts (this kit's own runs, 2026-10-26)

| Config | Engine | Vendor pair | Our lever | Exit |
|---|---|---|---|---|
| 8.3.6 distro CLI | — | **UNPATCHED** (floor 8.3.36) | — | **2** |
| 8.3.36 / 8.5.12 builds | — | PATCHED (companion line prints) | — | 0 |
| 8.3.6 venue | Apache prefork | **UNPATCHED** | chain LIKELY | **2** |
| 8.3.36, **zero ini** | Apache prefork | PATCHED | pubstate **ARMED** — dial-back `www-data` | 0 |
| 8.5.12, stock ini | mod_php (docker) | PATCHED | chain LIKELY — dial-back `www-data` | 0 |
| 8.5.12 | FPM + nginx | PATCHED | pubstate **3/3** — dial-back `www-data` | 0 |
| 8.3.36, proven ini | php -S, `setarch -R` | PATCHED | spray **5/5** byte-identical, `shell: YES` | 0 |

Five shells collected on five distinct configs (prefork, prefork-patched,
FPM, mod_php, php -S), one dial-back identity receipt each, all
first-try. A dedicated reproduction run popped the whole fleet in
**~2 seconds** and a repeat leg 54 seconds later returned an identical
banner — reproducible, not a one-shot fluke. Every shell banner dials
back with the `php2shell-revshell-OK` handshake marker (historical name,
not a version readout — it dials correctly from 8.5.12 too).

`kit selftest` ships green: **16/16 PASS** from the committed tree on
the author's box, 2026-10-26 — the same command a stranger runs first.

## Layout

```
kit                  python3 dispatcher (stdlib only)
detect/              single-file checker (PHP 5.4+, exit-code contract) + runners
prove/               staleness spray · vendor regression-shape arms
exploit/             staleness chain · pubstate lever · app census
bench/               setarch -R php -S harness + docroot apps + arm docroot
```

## Portability

- `python3` stdlib runners; PHP 5.4+ single-file apps; no PHP
  extensions beyond stock session/rfc1867.
- `bash` only for the local bench launchers; payloads wrap in
  `bash -c` (dash has no `/dev/tcp`). Checker itself is Windows/IIS-safe
  by construction (no POSIX calls) — untested on real IIS hardware, and
  the kit says so rather than hiding it.
- Environment-agnostic: the kit knows PHP, not the author's lab. Venue
  facts are printed terrain (`kit targets`); build discovery is
  on-box (`kit versions`); `PHP2SHELL_PROJ` optionally points at a
  php-src project tree for the local arms.
- Survives `tar czf` + a Windows share. Runtime droppings
  (`__pycache__`, detect logs, `bench/sessions/`) are gitignored.

## Scope & status

- The staleness lever is **uncatalogued upstream** — no CVE, not yet
  reported. Prior art is this repo's timestamp: first commit
  **2026-10-21**. Whoever wants to file the report is welcome to;
  the date is on the record either way.
- Determinism claims are **per-machine** (byte-identical run-to-run
  under `setarch -R`), ~stable — not identical — across boxes.
- Cross-request corruption (the 618-a leg) is concealed on stock
  `cleanup=1` and was never part of the staleness chain; php -S single
  workers are structurally immune to it — negative control, not a
  target read.

MIT licensed. Research published openly — public on GitHub since
2026-10-21, no strings attached.
