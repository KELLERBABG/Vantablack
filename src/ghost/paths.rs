//! Where Global Ghost Net keeps its files.
//!
//! Older builds wrote `identity.key`, `peers.cache`, `ghost-consumer.json`,
//! `ghost.log` and `ghost-topology.json` into the *current working directory*.
//! That made the binary behave differently depending on where it was launched
//! from: double-clicking a copy on the desktop silently generated a brand-new
//! identity, so a node "forgot" its fingerprint — and therefore its pairings —
//! the moment the .exe moved. It also meant that launching from a read-only or
//! non-writable directory (say `C:\Program Files`) could not persist anything.
//!
//! Every desktop application solves this the same way, and so does this module:
//! state lives in one per-user application-data directory, and the location of
//! the executable — or the shell's current directory — is irrelevant.
//!
//! * Windows: `%APPDATA%\GlobalGhostNet`
//! * macOS:   `~/Library/Application Support/GlobalGhostNet`
//! * Linux:   `$XDG_DATA_HOME/global-ghost-net` (or `~/.local/share/global-ghost-net`)
//!
//! `GHOST_DATA_DIR` overrides the whole thing, which is what the test suite and
//! the sandboxed CI runs use. The older per-file overrides
//! (`GHOST_IDENTITY_FILE`, `GHOST_CONSUMER_CONFIG`, `GHOST_LOG`) still win over
//! the default, so existing scripts and service units keep working.

use std::path::{Path, PathBuf};

/// Overrides the application-data directory outright.
pub const DATA_DIR_ENV: &str = "GHOST_DATA_DIR";

/// Directory name used on Windows and macOS (Linux uses the XDG-style name).
pub const APP_DIR_NAME: &str = "GlobalGhostNet";

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// The platform's per-user application-data directory for this app.
fn platform_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        // Roaming first: a domain user's settings and identity follow them
        // between machines, exactly as they would for any other desktop app.
        for key in ["APPDATA", "LOCALAPPDATA"] {
            if let Some(base) = non_empty_env(key) {
                return Some(Path::new(&base).join(APP_DIR_NAME));
            }
        }
        non_empty_env("USERPROFILE").map(|home| {
            Path::new(&home)
                .join("AppData")
                .join("Roaming")
                .join(APP_DIR_NAME)
        })
    }
    #[cfg(target_os = "macos")]
    {
        non_empty_env("HOME").map(|home| {
            Path::new(&home)
                .join("Library")
                .join("Application Support")
                .join(APP_DIR_NAME)
        })
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = non_empty_env("XDG_DATA_HOME") {
            return Some(Path::new(&xdg).join("global-ghost-net"));
        }
        non_empty_env("HOME").map(|home| {
            Path::new(&home)
                .join(".local")
                .join("share")
                .join("global-ghost-net")
        })
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        None
    }
}

/// The directory the application owns. Pure: no directory is created and no
/// filesystem is touched, so this is safe to call for logging or diagnostics.
///
/// Returns the current working directory only when the OS gives us nothing to
/// work with, which keeps the historic behaviour as a last resort.
pub fn data_dir() -> PathBuf {
    if let Some(explicit) = non_empty_env(DATA_DIR_ENV) {
        return PathBuf::from(explicit);
    }
    platform_data_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Resolve a state-file name to its real path inside [`data_dir`].
///
/// A bare filename (`"identity.key"`) is placed in the application-data
/// directory. Anything the caller spelled out — an absolute path, or one
/// containing a separator — is returned untouched, because that is an explicit
/// instruction rather than a default.
pub fn data_file(name: &str) -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    resolve(&data_dir(), &cwd, name)
}

/// Same as [`data_file`], for the many call sites that want a `String`.
pub fn data_file_string(name: &str) -> String {
    data_file(name).to_string_lossy().into_owned()
}

/// True when `name` is a bare filename rather than a path the user chose.
fn is_bare_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\\'])
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The testable core of [`data_file`]: place `name` inside `dir`, making sure
/// the directory exists and carrying over a file an older build left in `cwd`
/// the first time it is needed.
fn resolve(dir: &Path, cwd: &Path, name: &str) -> PathBuf {
    if !is_bare_name(name) {
        // The caller spelled out a path; honour it exactly.
        return PathBuf::from(name);
    }
    let target = dir.join(name);
    if !same_dir(dir, cwd) {
        // The directory has to exist before anyone writes the file into it —
        // the very first thing a fresh install does is save an identity key.
        if !dir.exists() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                tracing::warn!(dir = %dir.display(), error = %e, "Could not create the application data directory");
            }
        }
        if !target.exists() {
            adopt(&cwd.join(name), &target);
        }
    }
    target
}

/// Carry a file from an older build's working directory into the data dir.
///
/// This copies rather than moves: the original is never touched, so a failed
/// copy cannot lose someone's identity key. It is logged, because the user
/// still has a stale duplicate sitting in their old working directory.
fn adopt(legacy: &Path, target: &Path) {
    if !legacy.is_file() {
        return;
    }
    match std::fs::copy(legacy, target) {
        Ok(_) => tracing::info!(
            from = %legacy.display(),
            to = %target.display(),
            "Migrated an existing file into the application data directory"
        ),
        Err(e) => tracing::warn!(
            from = %legacy.display(),
            to = %target.display(),
            error = %e,
            "Could not migrate file into the application data directory"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A unique, empty directory under the system temp dir.
    fn scratch(tag: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ggn_paths_{}_{}_{}", std::process::id(), id, tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bare_names_land_in_the_data_dir() {
        let data = scratch("bare");
        let cwd = scratch("cwd");
        assert_eq!(
            resolve(&data, &cwd, "identity.key"),
            data.join("identity.key")
        );
    }

    #[test]
    fn explicit_paths_are_left_alone() {
        let data = scratch("explicit");
        let cwd = scratch("cwd2");
        // Absolute paths, and anything the caller spelled with a separator.
        let abs = if cfg!(windows) {
            "C:\\tmp\\a.key"
        } else {
            "/tmp/a.key"
        };
        assert_eq!(resolve(&data, &cwd, abs), PathBuf::from(abs));
        assert_eq!(
            resolve(&data, &cwd, "./nested/a.key"),
            PathBuf::from("./nested/a.key")
        );
        assert_eq!(
            resolve(&data, &cwd, "sub/a.key"),
            PathBuf::from("sub/a.key")
        );
    }

    #[test]
    fn a_file_left_in_the_working_directory_is_adopted_once() {
        let data = scratch("adopt");
        let cwd = scratch("adopt_cwd");
        std::fs::write(cwd.join("identity.key"), b"legacy-seed").unwrap();

        let resolved = resolve(&data, &cwd, "identity.key");
        assert_eq!(resolved, data.join("identity.key"));
        assert_eq!(std::fs::read(&resolved).unwrap(), b"legacy-seed");
        // The original is copied, never moved — losing an identity key to a
        // failed migration would be unforgivable.
        assert!(cwd.join("identity.key").exists());
    }

    #[test]
    fn an_existing_data_file_is_never_overwritten_by_the_legacy_one() {
        let data = scratch("keep");
        let cwd = scratch("keep_cwd");
        std::fs::write(data.join("identity.key"), b"authoritative").unwrap();
        std::fs::write(cwd.join("identity.key"), b"stale").unwrap();

        let resolved = resolve(&data, &cwd, "identity.key");
        assert_eq!(std::fs::read(&resolved).unwrap(), b"authoritative");
    }

    #[test]
    fn nothing_is_copied_when_the_data_dir_is_the_working_directory() {
        let cwd = scratch("same");
        let path = cwd.join("identity.key");
        std::fs::write(&path, b"only-copy").unwrap();

        let resolved = resolve(&cwd, &cwd, "identity.key");
        assert_eq!(resolved, path);
        assert_eq!(std::fs::read(&resolved).unwrap(), b"only-copy");
    }

    #[test]
    fn the_default_data_dir_is_per_user_and_absolute() {
        // Explicit overrides are someone else's contract, and `resolve` is
        // covered above; this is only about what the platform default looks
        // like, so that it can never be "wherever the .exe happens to be".
        if non_empty_env(DATA_DIR_ENV).is_some() {
            return;
        }
        let dir = data_dir();
        assert!(!dir.as_os_str().is_empty());
        assert!(dir.is_absolute(), "{} is not absolute", dir.display());
        let expected = if cfg!(windows) || cfg!(target_os = "macos") {
            APP_DIR_NAME
        } else {
            "global-ghost-net"
        };
        assert!(
            dir.ends_with(expected),
            "{} does not end with {expected}",
            dir.display()
        );
    }
}
