# Building and verifying on Windows

The repository pins `channel = "stable"` in `rust-toolchain.toml`. That is not the
whole story on Windows, where the compiler choice decides whether the build works
at all.

## Why the choice matters

`reqwest` reaches `ring`, and `ring` compiles C. So a Rust toolchain is not enough;
there has to be a working C compiler and linker behind it.

- **`x86_64-pc-windows-gnu` (the rustup default on many machines).** Needs a gcc
  that can build `ring`'s `curve25519.c`. A broken or mismatched mingw install
  fails this with `cc-rs` reporting `Compiler family detection failed`, or with a
  bare `gcc -c` that exits non-zero and writes nothing. The error text names
  `ring`, which makes it read like a project defect.
- **`x86_64-pc-windows-msvc`.** Needs `link.exe` from a Visual Studio developer
  environment and the Windows SDK import libraries (`kernel32.lib` and friends).
  A Visual Studio install with the C++ workload but without the Windows SDK
  component fails at link time with `LNK1181: cannot open input file
  'kernel32.lib'`, which is the confusing one: the compiler ran fine.

Either install is a supported path. Pick one and check it before blaming the code.

## MSVC

```powershell
# Visual Studio must have "Desktop development with C++" AND the Windows SDK component.
& .\scripts\cargo-msvc.ps1 -TargetDir C:\build\vb check --all-targets
& .\scripts\cargo-msvc.ps1 -TargetDir C:\build\vb test --no-default-features --lib
```

The script locates Visual Studio with `vswhere` and runs cargo inside `vcvars64`,
because cargo cannot link on its own. It also verifies that the Windows SDK import
libraries are present before starting cargo, and tells you so if they are not.

### When the Windows SDK component is absent

Both halves of the SDK are on NuGet, and together they are enough to build the
project on a machine whose Visual Studio install lacks the SDK component. This
was verified on such a machine: `check --all-targets` with the default features
compiles the desktop stack (`tray-icon`, `tao`, `webview2-com`) and the tests.

```powershell
# Import libraries (kernel32.lib, ucrt.lib, msvcrt.lib's siblings and the rest)
$x = '10.0.26100.4188'
Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.x64/$x/microsoft.windows.sdk.cpp.x64.$x.nupkg" -OutFile libs.zip
Expand-Archive libs.zip -DestinationPath C:\build\sdkx64

# C headers (ucrt stddef.h and friends), which the x64 package does not carry
$v = '10.0.28000.2705'
Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp/$v/microsoft.windows.sdk.cpp.$v.nupkg" -OutFile sdk.zip
Expand-Archive sdk.zip -DestinationPath C:\build\sdk

& .\scripts\cargo-msvc.ps1 -TargetDir C:\build\vb `
    -SdkLibDir C:\build\sdkx64\pkg `
    -SdkIncludeDir C:\build\sdk\pkg\c\Include `
    check --all-targets
```

The x64 package holds the import libraries under `c\um\x64` and `c\ucrt\x64`;
`-SdkLibDir` adds both to `LIB`. The metapackage holds the headers under
`c\Include\<version>\{ucrt,um,shared,winrt}`; `-SdkIncludeDir` finds the newest
version directory and adds those four to `INCLUDE`. Without the headers the C
compiler stops at `fatal error C1083: Cannot open include file: 'stddef.h'`
while building `ring`, and without the libraries the link stops at
`LNK1104: cannot open file 'msvcrt.lib'`.

If running a downloaded `.ps1` is refused with an `UnauthorizedAccess` error, the
machine's execution policy is Restricted (the Windows default). Either invoke it
through a process-scoped bypass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\cargo-msvc.ps1 -TargetDir C:\build\vb check
```

or unblock the file once with `Unblock-File .\scripts\cargo-msvc.ps1`. The script
itself checks for `kernel32.lib` on `LIB` before starting cargo, so a Visual
Studio install that lacks the Windows SDK component is reported as that, rather
than as a link failure minutes later.

## Linux, including WSL

```bash
./scripts/build-gate.sh check --lib --no-default-features
./scripts/build-gate.sh test --no-default-features
```

Linux needs no Windows SDK, and `ring`'s C builds with the system gcc. Under WSL,
give cargo a target directory inside the Linux filesystem (`/tmp/...`), which the
script does, rather than writing every object file across the 9p mount.

Building the desktop features (`webview`, `tray`) additionally needs GTK and
WebKit development headers; `--no-default-features` is the server and library
build and needs none of them:

```
Debian / Ubuntu  sudo apt install pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev \
                     libayatana-appindicator3-dev librsvg2-dev
Fedora           sudo dnf install pkgconf webkit2gtk4.1-devel gtk3-devel \
                     libappindicator-gtk3-devel librsvg2-devel
```

Assembling that closure without root is not worth attempting: `apt-cache depends`
walks 498 packages for those four `-dev` packages plus `pkgconf`, and each one has
to be downloaded, extracted into a prefix, and have its `.pc` files rewritten to
point at that prefix instead of `/usr`. The desktop build is verified on Windows
(the section above) and in CI; `--no-default-features` covers everything that
does not touch GTK.

## What CI runs, and what that covers

`.github/workflows/ci.yml` installs the GTK/WebKit headers on Ubuntu and builds
the default features, so the desktop path is compiled somewhere even when a
contributor only builds `--no-default-features` locally. The per-platform jobs
(Windows installer, Windows Wintun, Android APK, Docker netem) are the only places
those paths are exercised; none of them is reproducible on a Linux workstation,
and none is a substitute for running the Rust test suite yourself.

Both build scripts take any cargo subcommand, so the gates above are one command
each:

```bash
./scripts/build-gate.sh check --all-targets --no-default-features --features vpn
./scripts/build-gate.sh test  --all-targets --no-default-features --features vpn
./scripts/build-gate.sh clippy --all-targets --no-default-features --features vpn -- -D warnings
```

`--features vpn` is what makes the `vpn_*` tests run rather than compile to an
empty harness; without it they report `0 passed` and prove nothing.

## Running the formal models

`formal/*.pv` needs ProVerif. CI builds it from source; without OCaml installed,
the Windows binary package is the shorter route:

```powershell
Invoke-WebRequest https://bblanche.gitlabpages.inria.fr/proverif/proverifbin2.05.tar.gz -OutFile pv.tar.gz
tar -xzf pv.tar.gz
.\proverif2.05\proverif.exe formal\ghost_session.pv
.\proverif2.05\proverif.exe formal\shardsec_space_time.pv
```
