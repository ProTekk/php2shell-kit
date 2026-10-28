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

## Groom port result (vendor-ordered placement, tested 2026-10-27)

The vendor's ordering trick (file1 fires the free mid-request, 149 groom fields arrive
after the free, file2's stores arrive after the fields) was ported and run on four
engines including LiteSpeed's own builds — `lsphp 8.3.36` and `lsphp 8.5.12` (inline-bucket
era, OpenLiteSpeed 1.9.4), plus 8.3.6 and patched mod_php 8.5.12. Every run returned
HEALED: the counter advances fully (`bytes == clen`) and no field shows store damage
(`WINDOWS=0`), 12/12 runs. Explanation: between the core's `track_init()` free and its
same-function re-decode there is no allocation window any request-level data can enter —
PHP's re-decode pops the freed block itself. The vendor's published field-landing is
therefore lab-state-dependent (busy/concurrent heap), not a property of the published
request ordering alone. A deterministic slot-collision sweep (28 key names) found no
session key owning the store's fixed slot. This leaves attacker-controlled placement —
and with it the forged-handler hijack — open for anyone, us included; what IS demonstrated
on every venue is that the dispatch callee identity (`__unserialize`) comes from the
attacker's payload.

Busy-heap sweep (2026-10-28 night): planted 5-key arrays (bin-stuffed to 20)
+ 256B string carriers + 512B int-slot arrays, 8 trials x 3 allocator regimes
— distro zend-MM prefork, unpatched 8.5.11 ASAN with `USE_ZEND_ALLOC=0`
(vendor-lab allocator semantics), 8.3-era twin — **0/120 landed**. The vendor's
busy-heap `WINDOWS>0` does not reproduce under request-level placement even
when zend-MM is swapped for ASAN-intercepted malloc. Both remaining doors
closed the same night: the threaded door died with the mechanism (ZTS gives
each thread a PRIVATE zend MM heap — no SAPI shares one PHP heap across
requests; ZTS+mpm_event venue under churn: 0/60), and header-shape adjacency
count x byte-size on R1/R2: 0/92. The authoring door closed structurally:
raw-LF progress keys author session-file LINES (kernel-observed) but author
KEYS only — the engine's serialized entry always trails the first pipe, and
pipes inside attacker key bytes are rejected at encode, so serialized objects
are unauthorable via this channel; stock `cleanup=1` keeps the file empty at
rest, so authored lines never reach a next request, and 8.5.11 decode failure
is silent. Net: placement and authoring are request-level-closed on stock
config — the shell that pops is app-gated (the vendor's position), and it
pops reliably. One venue lesson, free of charge: on stock-ini mod_php, ANY
echo during `session_start()`
decode (e.g. from `__unserialize`) trips the cache limiter and aborts the
NEXT request's session start (`WSTARTED=NONE`) — buffer pre-header echoes.

## What this kit is

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
- **Audit settlement (2026-10-27, independent code review, agreed)**:
  the staleness-chain shell stays corruption-gated; the **pubstate
  default run is a window-reachability receipt, not a corruption
  receipt** — its gate (session active + body present) is satisfiable
  without the alleged corruption event, and the default skips the
  corruption stage by design. Neither grade touches the underlying
  condition, which reproduces on untouched builds.
- **Caller leg, sinkless (2026-10-27)**: session-decode dispatch —
  `__unserialize` + `__destruct` through `zend_call_function` — fires
  5/5 on five venues (distro 8.3.6 `php -S` + Apache prefork, patched
  8.3.36 vendor venue, 8.5.12 mod_php) with an **echo-only app**: no
  `system`/`exec`/`eval` sink anywhere in its source. Controlled
  execution *through a forged handler* is still the open rung — store
  placement, not dispatch, gates the endgame.

## Receipts (this kit's own runs, 2026-10-26 → 27)

| Config | Engine | Vendor pair | Our lever | Exit |
|---|---|---|---|---|
| 8.3.6 distro CLI | — | **UNPATCHED** (floor 8.3.36) | — | **2** |
| 8.3.36 / 8.5.12 builds | — | PATCHED (companion line prints) | — | 0 |
| 8.3.6 venue | Apache prefork | **UNPATCHED** | chain LIKELY | **2** |
| 8.3.36, **zero ini** | Apache prefork | PATCHED | pubstate **ARMED** — dial-back `www-data` | 0 |
| 8.5.12, stock ini | mod_php (docker) | PATCHED | chain LIKELY — dial-back `www-data` | 0 |
| 8.5.12, stock ini | mod_php (source Apache, .16) | PATCHED | pubstate **3/3** — dial-back `daemon` | 0 |
| 8.5.12 | FPM + nginx | PATCHED | pubstate **3/3** — dial-back `www-data` | 0 |
| 8.3.36, proven ini | php -S, `setarch -R` | PATCHED | spray **5/5** byte-identical, `shell: YES` | 0 |
| **8.6.0RC4** (8.6 era) | php -S, `setarch -R` | PATCHED (markers 10× in source) | spray **5/5** byte-identical `205,335/517,337`, `shell: YES` | 0 |

The 8.6.0RC4 row is the era-extender: built from the RC tag the night it
shipped, vendor fix markers present 10× — and the frozen counter reads
**byte-identical to the 8.3.x harness numbers** on a machine 1000 km and
three PHP majors away. The lever now spans 8.3 → 8.6.

Five shells collected on five distinct configs (prefork, prefork-patched,
FPM, mod_php, php -S), one dial-back identity receipt each, all
first-try. A dedicated reproduction run popped the whole fleet in
**~2 seconds** and a repeat leg 54 seconds later returned an identical
banner — reproducible, not a one-shot fluke. Every shell banner dials
back with the `php2shell-revshell-OK` handshake marker (historical name,
not a version readout — it dials correctly from 8.5.12 too).

`kit selftest` ships green: **16/16 PASS** from the committed tree on
the author's box, 2026-10-26 — the same command a stranger runs first.

## CTF field notes — Cloudflare php-rce (night 2026-10-27 → 28)

The night was spent on a live CTF box and its faithful ASAN twins
(8.5.11 on `php -S` and prefork mod_php, empty docroot) — the same
`upload_progress` street this kit patrols. The laws that generalize to
any venue, with the kit's take on each:

- **SID provenance (source + wire).** The upload-progress SID comes
  from the multipart body field named `PHPSESSID` (works without any
  cookie) or the `Cookie` header — cookie takes precedence. URL query
  is never scanned for it (`use_only_cookies` is compiled in) and no
  SID means the whole session cycle is skipped. The kit's chain probe
  already rides the cookie; a body-field plant is the fallback for
  cookie-less venues.
- **First-seen-key law.** One progress entry per request, keyed by the
  *first* progress-field value. Multi-field POSTs don't fan out.
- **Write-reject oracle.** A pipe byte in the progress value lands
  byte-exact into the session-file key, breaks `PS_DELIMITER`
  serialization at write, and the origin prints "Failed to write
  session data. Data contains invalid key" in the response body
  (~176 bytes on empty-docroot apps) — deterministic, self-inflicted,
  needs no persistence and no app code. Display-errors-gated.
- **Double-write law (stock `cleanup=1`).** RSHUTDOWN writes the
  session data, cleanup deletes the progress entry, then the progress
  writer flushes `''` again — the session file is *constant empty at
  rest*. No readback/persistence chain can fire on a stock box; the
  channels out are parse-window warnings, the Set-Cookie machinery
  bit, latency, and crashes. This corroborates the kit's `cleanup=1`
  LIKELY tier and why the pubstate lever never leans on persistence.
- **Armed ≠ vulnerable; unpatched ≠ armed.** The live box ran
  compile-default ini (no php.ini): `memory_limit=-1`, so the vendor
  OOM producers can never arm — and the ASAN twin on *unpatched*
  8.5.11 produced **zero reports** replaying the full traffic
  vocabulary (first such ASAN receipt on record; vendor audit notes
  0/29 repos ever posted one). A silent response on stock config
  proves nothing about patch state in either direction — the kit's
  probe-beats-lineage stance holds.
- **WAF multipart window (proven on the live wall, 2026-10-28).** Cloudflare's
  PHP2Shell rules inspect a positional ~1 MB window: a bare
  `PHP_SESSION_UPLOAD_PROGRESS` field inside the window 403s on the NAME
  alone (value-independent — clean and pipe values alike), while the identical
  request with a 1.4 MB filler field ahead of it passes and the origin answers
  with the write-reject oracle in the body. So: pad first, then progress.
  The rules are live-evolving (the same shape passed the same wall the night
  before) — re-verify the un-padded control shot on any test day before
  claiming a bypass. Applies to any cloud-fronted target.
- **Delivery envelope and transport laws (live, 2026-10-28 evening).**
  A front Worker imposed a ~10 MB body budget (chunked included — a
  Worker limit, not the PHP `post_max_size` gate; 12.2 MB chunked and
  12.5 MB CL bodies both 413 with a 48-byte JSON, no origin hit). With
  a declared Content-Length the origin's `post_max_size` (8M default)
  gates the whole POST — keep exploit bodies under it.
  `upload_max_filesize` (2M default) is a trap with an inversion: file
  parts **over** 2M abort cleanly before any tmp spool and the venue
  answers fine, while parts in the ~0.3–1.9 MB range spool fully and
  *stall mod_php mid-parse* — no response, no error, worker never
  returns (observed on the live container and both local prefork
  venues; the same-shaped death, one venue at a time). Transport shape
  decides survival: raw HTTP/1.1 **burst** bodies with file parts
  ≥300 KB die at origin timeout, the same bytes **dripped** in 64 KB
  slices over ≥10 s return 200 — and the drip is not just survival, it
  is the only thing that paces the origin: `min_freq` upload-progress
  windows only elapse when bytes arrive over time, so behind a proxy
  the attacker's own write cadence arms the machinery. HTTP/2 (curl
  ALPN) bursts survive fine. Same body bytes always return the same
  front-end attempt UUID — payloads are content-addressed at the edge,
  so retries cost nothing in bookkeeping.
- **The public chain's consumer is SAPI-shaped.** The circulating
  109619 bodies lean on FPM/LiteSpeed semantics (mid-stream `min_freq`
  frees, next-request decode on a persistent worker). On mod_php behind
  a buffering proxy, with an empty app whose session file is
  `cleanup=1`-empty at rest, the forged `zend_call_function` dispatch
  never fires in lab or live (plausible and garbage call addresses
  alike return silent 200s). A shell there needs a *manufactured*
  consumer and a per-boot text base for PIE ASLR — that discovery is
  the missing lever, not placement luck.

CTF-local, for the record: the live box's "loud era" fatals were a
boot-transition effect (integer-overflow fatal numbers were
uninitialized-heap garbage, not body bytes), and the app was an
empty `index.php` — the machinery armed even there, which is this
kit's core premise (the feature writes before app code runs)
demonstrated on a stranger's production box.

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
