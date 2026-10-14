//! Atomic file replace (Phase 4, M2 step 2): the temp+rename dance.
//!
//! A daemon must never re-parse a half-written config (SIGHUP can
//! land between two `write` syscalls). Every file configd installs is
//! therefore written to a fresh temp file **in the destination
//! directory** (same filesystem — rename stays atomic), flushed to
//! disk, then renamed over the destination. POSIX `rename` replaces
//! the target atomically: a reader sees either the whole old file or
//! the whole new one, never a mix.
//!
//! The temp name carries the pid so two configd invocations never
//! collide on it, and is removed on every failure path before the
//! error propagates.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Writes `contents` to `dest` atomically (temp + fsync + rename).
///
/// Creates the destination directory if it does not exist (the
/// `--etc-dir` of a fresh deployment may not yet).
pub fn write_atomic(dest: &Path, contents: &str) -> io::Result<()> {
    if let Some(dir) = dest.parent() {
        fs::create_dir_all(dir)?;
    }
    let temp: PathBuf = dest.with_file_name(format!(
        ".{}.configd.tmp.{}",
        dest.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string()),
        std::process::id()
    ));
    // Failure past this point must not leave the temp file behind.
    if let Err(err) = write_and_rename(&temp, dest, contents) {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    Ok(())
}

fn write_and_rename(temp: &Path, dest: &Path, contents: &str) -> io::Result<()> {
    {
        // create_new: a leftover temp from a SIGKILLed predecessor is
        // an error, not something to silently build on.
        let mut file = fs::File::options()
            .write(true)
            .create_new(true)
            .open(temp)?;
        io::Write::write_all(&mut file, contents.as_bytes())?;
        // Flush the file contents before the rename makes them
        // visible (directory durability is the fs's business; v1 does
        // not fsync the parent dir — disclosed in docs).
        file.sync_all()?;
    }
    fs::rename(temp, dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_content_readable_back() {
        let dir = std::env::temp_dir().join(format!("configd-atomic-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("savd.conf");
        write_atomic(&dest, "mode strict\n").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "mode strict\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn replaces_existing_file_wholesale() {
        let dir =
            std::env::temp_dir().join(format!("configd-atomic-replace-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("rouster.conf");
        fs::write(&dest, "old contents that were longer\n").unwrap();
        write_atomic(&dest, "new\n").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "new\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaves_no_temp_file_behind() {
        let dir = std::env::temp_dir().join(format!("configd-atomic-notmp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("bfdd.conf");
        write_atomic(&dest, "peer 10.0.0.1\n").unwrap();
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "leftover temps: {leftovers:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn creates_missing_destination_directory() {
        let dir = std::env::temp_dir().join(format!(
            "configd-atomic-mkdir-{}/{}/deep",
            std::process::id(),
            std::process::id() % 7
        ));
        let _ = fs::remove_dir_all(
            std::env::temp_dir().join(format!("configd-atomic-mkdir-{}", std::process::id())),
        );
        let dest = dir.join("ospfd.conf");
        write_atomic(&dest, "router ospf\n").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "router ospf\n");
        let _ = fs::remove_dir_all(
            std::env::temp_dir().join(format!("configd-atomic-mkdir-{}", std::process::id())),
        );
    }

    #[test]
    fn second_write_with_same_pid_replaces_cleanly() {
        // Same process: the temp name collides only if a leftover
        // survived, which the failure-path cleanup prevents — the
        // normal path renames it away. Two writes in a row prove the
        // name is free again.
        let dir = std::env::temp_dir().join(format!("configd-atomic-twice-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("bgpd.conf");
        write_atomic(&dest, "one\n").unwrap();
        write_atomic(&dest, "two\n").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "two\n");
        let _ = fs::remove_dir_all(&dir);
    }
}
