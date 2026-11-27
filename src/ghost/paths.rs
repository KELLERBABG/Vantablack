//! Where Vantablack keeps its files.
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
//!
//! There is a second, deliberately *separate* location for regenerable data:
//! [`cache_dir`]. The identity key and the device names are small and should
//! follow a roaming profile between machines; the WebView2 user-data folder is
//! a browser cache and must not, which is why it is not simply a subdirectory of
//! [`data_dir`].

use std::path::{Path, PathBuf};

pub const DATA_DIR_ENV: &str = "GHOST_DATA_DIR";

pub const CACHE_DIR_ENV: &str = "GHOST_CACHE_DIR";

pub const APP_DIR_NAME: &str = "GlobalGhostNet";

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn platform_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
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

pub fn data_dir() -> PathBuf {
    if let Some(explicit) = non_empty_env(DATA_DIR_ENV) {
        return PathBuf::from(explicit);
    }
    platform_data_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn platform_cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(base) = non_empty_env("LOCALAPPDATA") {
            return Some(Path::new(&base).join(APP_DIR_NAME));
        }
        non_empty_env("USERPROFILE").map(|home| {
            Path::new(&home)
                .join("AppData")
                .join("Local")
                .join(APP_DIR_NAME)
        })
    }
    #[cfg(target_os = "macos")]
    {
        non_empty_env("HOME").map(|home| {
            Path::new(&home)
                .join("Library")
                .join("Caches")
                .join(APP_DIR_NAME)
        })
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = non_empty_env("XDG_CACHE_HOME") {
            return Some(Path::new(&xdg).join("global-ghost-net"));
        }
        non_empty_env("HOME").map(|home| Path::new(&home).join(".cache").join("global-ghost-net"))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        None
    }
}

pub fn cache_dir() -> PathBuf {
    cache_dir_with(non_empty_env(CACHE_DIR_ENV))
}

fn cache_dir_with(explicit: Option<String>) -> PathBuf {
    explicit
        .map(PathBuf::from)
        .unwrap_or_else(|| platform_cache_dir().unwrap_or_else(data_dir))
}

pub fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)
}

pub fn data_file(name: &str) -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    resolve(&data_dir(), &cwd, name)
}

pub fn data_file_string(name: &str) -> String {
    data_file(name).to_string_lossy().into_owned()
}

fn is_bare_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\\'])
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn resolve(dir: &Path, cwd: &Path, name: &str) -> PathBuf {
    if !is_bare_name(name) {
        return PathBuf::from(name);
    }
    let target = dir.join(name);
    if !same_dir(dir, cwd) {
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
    fn an_explicit_cache_dir_is_used_verbatim() {
        let abs = if cfg!(windows) {
            "C:\\ggn-cache"
        } else {
            "/tmp/ggn-cache"
        };
        assert_eq!(cache_dir_with(Some(abs.to_string())), PathBuf::from(abs));
        assert_eq!(
            cache_dir_with(Some("relative/cache".to_string())),
            PathBuf::from("relative/cache")
        );
    }

    #[test]
    fn the_cache_dir_is_separate_from_the_data_dir() {
        if non_empty_env(DATA_DIR_ENV).is_some() || non_empty_env(CACHE_DIR_ENV).is_some() {
            return;
        }
        let cache = cache_dir();
        assert!(!cache.as_os_str().is_empty());
        assert!(cache.is_absolute(), "{} is not absolute", cache.display());
        let expected = if cfg!(windows) || cfg!(target_os = "macos") {
            APP_DIR_NAME
        } else {
            "global-ghost-net"
        };
        assert!(
            cache.ends_with(expected),
            "{} does not end with {expected}",
            cache.display()
        );
        assert_ne!(
            cache,
            data_dir(),
            "the cache must not live inside the roamed data directory"
        );
    }

    #[test]
    fn ensure_dir_creates_nested_paths_and_is_idempotent() {
        let base = scratch("ensure");
        let nested = base.join("a").join("b").join("c");
        ensure_dir(&nested).expect("first create");
        assert!(nested.is_dir());
        ensure_dir(&nested).expect("second create is a no-op");
        let file = base.join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(ensure_dir(&file).is_err());
    }

    #[test]
    fn the_default_data_dir_is_per_user_and_absolute() {
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
