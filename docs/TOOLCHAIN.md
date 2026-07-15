# Toolchain & Setup — Linux, macOS, Windows

Everything needed to build agent-bridle and to work the **formal-verification
track** (the Ceremony Contract's proof obligations — `docs/spec/
ceremony-contract.md` §6.2). Core contributors need §1 only; the formal track
adds §2.

Package managers assumed: **apt** (Debian/Ubuntu) on Linux, **Homebrew** on
macOS, **Chocolatey** on Windows. Anything not in a manager uses the tool's
official installer script.

**Verified state (2026-07-15):** §1 and the Lean/rustup halves of §2 are
exercised on Linux. The macOS and Windows columns and the full Aeneas build
follow upstream documentation and have not yet been executed here — trust,
then verify, then update this line.

---

## 0. Version pins (read these, don't hardcode)

Versions are pinned by files in the repos — the pin files are the source of
truth; the values below are a snapshot for orientation.

| Component | Pin file | Snapshot value |
|---|---|---|
| Rust (bridle) | `rust-toolchain.toml` (workspace, if present) / stable | stable |
| Rust (Charon) | `charon/rust-toolchain.toml` | `nightly-2026-06-01` + `rustc-dev`, `llvm-tools-preview`, `rust-src` |
| Charon commit (for Aeneas) | `aeneas/charon-pin` | managed by `make setup-charon` |
| Lean | `aeneas/backends/lean/lean-toolchain` | `leanprover/lean4:v4.31.0` (elan auto-fetches) |
| OCaml | Aeneas README | OCaml **5.x** (e.g. `5.3.0`) |

`rustup` and `elan` are version *managers*: they read the pin files and fetch
the right toolchain per directory. Install the managers; never hand-install a
pinned compiler.

## 1. Core toolchain (all contributors)

| Tool | Linux (apt) | macOS (brew) | Windows (choco) |
|---|---|---|---|
| git | `apt install git` | `brew install git` | `choco install git` |
| rustup | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | `brew install rustup` | `choco install rustup.install` |
| just | `cargo install just` (or `apt install just` on ≥ 23.04) | `brew install just` | `choco install just` |
| cargo-llvm-cov (optional) | `cargo install cargo-llvm-cov` | same | same |

> **Conflict warning (from Charon's own docs, applies generally):** uninstall
> any distro/brew-installed `rust`/`cargo` before using rustup — a stray
> system rust shadows the pinned toolchains in confusing ways. (`brew
> uninstall rust`, `apt remove rustc cargo`.) The brew *`rustup`* formula is
> fine; the brew *`rust`* formula is the hazard.

Then, in the repository:

```sh
just install-hooks   # mandatory — pre-push mirrors CI
just check           # fmt + clippy (-D warnings, both feature configs) + tests
```

`cargo-llvm-cov` is optional: the coverage recipe skips gracefully when it is
absent and enforces the 75% floor when present.

Windows note: `just` recipes assume a POSIX shell. Native builds work for the
Rust workspace, but run `just` from Git Bash — or do everything in WSL2
(Ubuntu) and follow the Linux column, which is the least-surprise path.

## 2. Formal-verification track (Lean · Charon · Aeneas)

The pipeline: **Charon** extracts pinned-nightly Rust to LLBC; **Aeneas**
(OCaml) translates LLBC to **Lean**; proofs live in Lean. You need all three
only to *regenerate or re-prove*; reviewing proofs needs Lean alone.

### 2.1 elan (Lean version manager)

| OS | Install |
|---|---|
| Linux | `curl https://elan.lean-lang.org/elan-init.sh -sSf \| sh` |
| macOS | `brew install elan-init` |
| Windows | PowerShell installer from the [elan releases](https://github.com/leanprover/elan/releases) (no reliable choco package; `scoop install elan` also works) |

No manual Lean install: elan reads `lean-toolchain` files per directory and
fetches the pinned version (first `lake build` in a Lean dir does the fetch).

### 2.2 OCaml + opam (for Aeneas)

| OS | Install opam | Notes |
|---|---|---|
| Linux | `apt install opam build-essential pkg-config m4` | then `opam init --auto-setup` and `eval $(opam env)` |
| macOS | `brew install opam` | same init |
| Windows | **Recommended: WSL2**, then the Linux column | opam ≥ 2.2 has native Windows support but the Aeneas dep stack is untested on it here; WSL2 is the supported path |

Create the OCaml 5 switch and install Aeneas's dependencies (list from the
Aeneas README — check it for drift before pasting):

```sh
opam switch create 5.3.0
eval $(opam env)
opam install calendar core_unix domainslib easy_logging menhir \
  ocamlformat.0.27.0 ocamlgraph odoc ppx_deriving ppx_deriving_yojson \
  progress unionFind visitors yojson zarith
```

### 2.3 Charon + Aeneas

```sh
git clone https://github.com/AeneasVerif/aeneas.git
cd aeneas
make setup-charon   # clones + builds Charon at the commit in ./charon-pin
                    # (uses rustup; auto-installs the pinned nightly)
make                # builds Aeneas
make test           # optional: exercises the pipeline end to end
```

Do **not** hand-clone Charon next to Aeneas unless you are developing Charon
itself — `make setup-charon` owns the pin. (Charon-only work: clone it and
`make build-charon-rust`; binary lands in `bin/charon`.)

### 2.4 Smoke checklist

Prove the setup end to end; every line should succeed:

```sh
rustup show                      # pinned toolchains visible
just check                       # bridle gate green
elan --version && lean --version # elan resolves a Lean
opam --version                   # ≥ 2.1 (≥ 2.2 on native Windows)
cd aeneas && make                # Aeneas builds
./bin/aeneas --help              # translator answers
```

## 3. What this enables

With §2 green, the Ceremony Contract's proof obligations (PO-1, PO-2 first)
run as: carve the pure decision kernel in `agent-bridle-core` → Charon
extracts LLBC → Aeneas emits Lean → theorems live in a `lake` project pinned
by its `lean-toolchain`. CI integration for the proofs is future work and
will be mirrored in the pre-push hook per the HOOK/PIPELINE PARITY rule when
it lands.

Refs: #225 (formal-track thread), `docs/spec/ceremony-contract.md` (the
obligations this toolchain discharges).
