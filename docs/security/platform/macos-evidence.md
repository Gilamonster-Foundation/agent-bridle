# macOS Seatbelt Evidence — zero Mach floor and named service grants (#405)

Evidence collected on:

- Host: macOS 26.6.2 (25G83), Darwin 25.6.0, arm64, `/usr/bin/sandbox-exec`
- Rust: stable toolchain via rustup; `cargo test -p agent-bridle-core --all-features`
- Branch: `feat/seatbelt-mach-service-grants`, based on `main` at `9df604c`

## Method

Every probe is a differential with a positive control (#361): the same
command runs unconfined (control), under the zero-floor `net:none` profile,
and under a profile that re-allows exactly one named service. A profile that
did not parse would never launch the child, so `/bin/echo ok` is run under each
confined profile first. The kernel denies a Mach lookup **silently** for these
children (no `Sandbox: deny(1) mach-lookup …` line reached the unified log for
`sandbox-exec` profiles on this host, and `(with report)` is rejected on a
`deny` action), so per-service need was established by function, not by log.

## Rows

| Row | Result | Evidence |
| --- | --- | --- |
| zero floor parses and runs tooling | RUNS | Under `(deny network*) (deny mach-lookup)` with no re-allow: `/bin/echo`, `/bin/sh -c`, `git add/commit/log/status` (identity configured), `cargo --version`, `xcrun --find swiftc`, `python3` importing `ssl`/`socket`/`subprocess` and loading 128 default CA certs all succeeded. CI proof: `net_none_mach_deny_still_runs_a_build_tool`. |
| uid → name needs `opendirectoryd.libinfo` | DIFFERENTIAL | `id -un`: unconfined prints the user name; zero floor prints the numeric uid; `mach:com.apple.system.opendirectoryd.libinfo` prints the name; `mach:com.apple.SecurityServer` alone prints the uid. `git commit` with no configured identity fails "Author identity unknown" under the zero floor and succeeds with the libinfo grant. CI proof: `net_none_mach_floor_is_zero_and_a_named_grant_reopens_that_service` (strict under `BRIDLE_REQUIRE_SEATBELT=1`; refuses to pass if the control cannot resolve a name). |
| keychain needs `SecurityServer` | DIFFERENTIAL | `security find-certificate -c nothing`: zero floor → `SecKeychainSearchCreateFromAttributes: One or more parameters passed to a function were not valid`; with `mach:com.apple.SecurityServer` → `SecKeychainSearchCopyNext: The specified item could not be found in the keychain` (the search ran). |
| resolver DNS closed under `net:none` | DENIED | `getaddrinfo("example.com")` → `nodename nor servname provided`; `curl https://example.com/` → `(6) Could not resolve host`. `com.apple.mDNSResponder` is not a candidate and is not granted, so the ADR 0015 "DNS exfiltration via the system resolver" residual is closed for the zero floor. |
| demonstrated deputy still closed | DENIED | E4 A/B/A differential `net_none_mach_floor_has_strict_ambient_closed_ambient_differential` passes under the zero floor: ambient legs `callback_success`, production leg `callback_error`. |
| per-candidate deputy status | UNKNOWN (withheld) | No candidate in `MACH_SERVICE_CANDIDATES` has native evidence that it cannot perform egress for the child; each is therefore denied unless granted. Known concerns to characterize before any is admitted to a default floor: `trustd.agent` (OCSP/CRL fetch), `launchservicesd`/`coreservicesd` (URL open via another app), `opendirectoryd.*` (directory-backed lookups on domain-joined hosts). |
| grant vocabulary fails closed | REFUSED | `mach:`, `mach:com.apple.*`, `mach:a b`, a quote, non-ASCII → `ToolError::Denied` before any profile is built (`mach_service_grants_validate_sort_and_dedup`); a grant under a loopback shape (no floor) is refused rather than accepted as a no-op (`mach_grant_refuses_when_malformed_or_floorless`). |
| admission unchanged | REFUSED | Every restricted Seatbelt net shape, `mach:` grants included, projects `Unknown` while `MACH_DEPUTY_AUDIT = Incomplete` (`every_restricted_network_scope_resolves_unknown`); the post-audit projection to `seatbelt-mach-service:<name>` classes and its closure-backed admission are pinned by `complete_audit_projects_grants_as_named_classes`. |

## Notes

- The E4 twelve-service list is retained verbatim as `MACH_SERVICE_CANDIDATES`
  so a host can name what it withheld; it is never emitted into a profile.
- `disclosure.mach_services` in the result envelope carries `granted` and
  `withheld` for a network-denied Seatbelt run and is omitted otherwise.
- Windows (AppContainer brokered services) is a separate native delegate and is
  not covered by this page.
