# Per-returned-token expiry regression

## Patch boundary

Fork: <https://github.com/SystasisIO/oidc-agent>, version
`5.3.8-systasis.1`, based on upstream `5.3.8` (`f31513ac`). The existing
Makefile derives `LIBMAJORVERSION=5`; Linux SONAME remains `liboidc-agent.so.5`.
No public `src/api` declarations, response fields or request capabilities change.
The [separate packaging note](PACKAGING.md) documents generated `.pc` metadata
and targeted daemon/library build and installation commands.

**The installed daemon serving the request must be patched. Replacing only
liboidc-agent/client binaries does not fix an already running upstream daemon.**
Restart the patched daemon and explicitly select its socket. If using a
forwarded socket, the daemon at the other end must also be this patched version.
The same requirement applies to an agent-service that starts/restarts the daemon.
Exact client package discovery is useful but does not attest to daemon identity.

The parser computes expiry for each returned access token, independently of
`SAVE_AT`. A default refresh replaces the cached token and expiry together;
explicit nonempty scopes/audiences replace neither. Empty strings are treated
as absent consistently with refresh's existing `SAVE_AT` rule. Each internal
access-token result carries its own expiry and owns its string, including
default refreshes and cache hits. Both token handlers free it after writing the
reply; temporary generation accounts can take ownership instead. No scope or
audience is stripped to force a cache hit.

Only a nonnegative integral `expires_in` JSON number or a nonempty decimal digit
string is accepted. `0` means expiry at the response time, not unknown lifetime.
Missing, negative, fractional, boolean, container, malformed or overflowing
values mean unknown expiry, reported as `expires_at: 0`. No JWT decoding,
previous-token expiry, default lifetime or copied OAuth implementation is used.
The resulting epoch must fit both `unsigned long` and nonnegative `time_t`,
because cache validity is checked using `time_t`. An epoch outside either range
is unknown, not a wrapped negative cached time.
A required missing/empty access token is an error and leaves the old cache intact.

## Focused target

Linux/ELF only: C99 compiler, GNU make, GNU-compatible linker with `--wrap` and
`--gc-sections`, pkg-config, Check, libcurl development files and libmicrohttpd
headers (included by the real daemon handler). cJSON and list use the bundled
upstream sources. On Debian/Ubuntu the focused dependencies are:

```sh
apt-get install build-essential pkg-config check libcurl4-openssl-dev libmicrohttpd-dev
```

The test uses upstream's Check `START_TEST`/`TCase` conventions. It compiles the
real token parser, refresh request builder, access-token flow, account setters,
account/issuer handlers and IPC formatter/pipe writer/reader. It mocks issuer
HTTP, the loaded-account database/encryption boundary, issuer/custom-parameter
configuration, log/help sinks and refresh-token persistence notification.
URL escaping uses libcurl. A wrapped clock fixes the exact epoch; wrappers also
observe the real IPC writer's token pointer and count its frees. Unexpected
autoload, confirmation, config loading or generation aborts the test.

The suite covers both account-name and issuer paths, scope-only, audience-only,
combined and empty-string requests, default cache hits and forced refresh,
nondefault-to-default consistency, unknown/invalid expiry, zero and integer
string expiry, unsigned/signed epoch overflow, errors/missing tokens, caller-owned memory, refresh
token rotation, multiple RFC 8707 resources and legacy audience mode. The
original parser entry points and access-token/ID-token ownership modes are
also exercised. No issuer network, JWT, account file or credentials are needed.
The signed-boundary regression accepts the maximum representable epoch, rejects
the next epoch, and covers `expires_in="9223372035154775808"` at
`TEST_NOW=1700000000` (plus its JSON-number form). Each case performs a subsequent
default request before assertions, exercising cache validity under UBSan.

The following commands are for the coordinator, not instructions to build in
the vendor checkout. Use an isolated source copy at `/build/oidc-agent-patched`:

```sh
make -C /build/oidc-agent-patched -f test/token_response_expiry/Makefile -j4 test
```

Equivalent convenience target using upstream's root Makefile:

```sh
make -C /build/oidc-agent-patched -j4 test-token-response-expiry
```

The standalone Makefile does not evaluate upstream's unrelated UI/build
dependency discovery. Objects and executable live under
`test/bin/token_response_expiry`; `BUILD_DIR` can select another output tree.
Run the normal and sanitizer commands serially, each with at most four jobs:

```sh
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 make -C /build/oidc-agent-patched \
  -f test/token_response_expiry/Makefile -j4 \
  BUILD_DIR=/build/oidc-agent-expiry-sanitized \
  SANITIZE='-fsanitize=address,undefined -fno-omit-frame-pointer' test
```

## RED on pristine, GREEN on patch

Prepare a separate pristine source tree from the pinned base, then copy **only
this test directory**, not patched production sources or VERSION. In a checkout
with the base commit available:

```sh
mkdir -p /build/oidc-agent-pristine
git -C /build/oidc-agent-patched archive f31513ac | tar -x -C /build/oidc-agent-pristine
cp -R /build/oidc-agent-patched/test/token_response_expiry /build/oidc-agent-pristine/test/
make -C /build/oidc-agent-pristine -f test/token_response_expiry/Makefile -j4 test
```

Expected RED: successful compile/link followed by nonzero test exit. Nondefault
replies contain the cached expiry instead of `TEST_NOW + 60`; unknown expiry
can retain a stale cached lifetime; audience-only results are not freed; default
results alias the cache. A compile/link failure is not regression evidence.

Run the identical target against `/build/oidc-agent-patched`; expected GREEN is
zero failed checks and exit zero. These tests deliberately use only entry points
available on the pristine base, so RED does not depend on new internal symbols.
Use a fresh output tree per source variant and sanitizer setting.

Build and live validation are owned by the coordinator. This patch author did
not build or execute tests. RED/GREEN and sanitizer outcomes must be recorded
after those commands run; the expected outcomes above are not observed results.
The focused suite does not prove daemon installation, forwarded-socket routing,
real issuer acceptance, DB encryption or an end-to-end application deployment.
