//! Build-time resource embedding for the Windows executables.
//!
//! The icon a user sees in Explorer, and the version block in the Properties
//! dialog, both have to be part of the PE image itself — they are not something
//! the program can set once it is running. `embed-resource` locates the
//! Windows SDK's `rc.exe` (or `windres` when cross-compiling) and links the
//! compiled `.res` into the named binaries.
//!
//! Nothing happens for non-Windows targets, and nothing happens for the console
//! tools: only `ggn` and its `vantablack` alias are the desktop application.
//! Regenerate the icons with `python scripts/make_icon.py`.

fn main() {
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");

    // `CARGO_CFG_TARGET_OS` is the platform being compiled *for*, which is what
    // decides whether a Windows resource is even meaningful.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    embed_resource::compile_for("assets/app.rc", ["ggn", "vantablack"], embed_resource::NONE);
}
