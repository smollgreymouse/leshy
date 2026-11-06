//! Process-lifetime writer lease (08D1 §31.2).
//!
//! One generated Leshy installation must have at most one live writer.
//! Exclusivity comes from a real OS lock — `flock(LOCK_EX|LOCK_NB)` on Unix,
//! `LockFileEx` exclusive/non-blocking on Windows — held from before
//! RouteManager construction until process exit. The lock file's *content is
//! never authority*: an abnormal process exit releases the OS lock, and a
//! leftover file never blocks a new holder.

use std::fs::OpenOptions;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;

/// A held exclusive writer lease. Drop (or process death) releases it.
#[derive(Debug)]
pub struct WriterLease {
    file: std::fs::File,
}

impl WriterLease {
    /// Takes an exclusive non-blocking OS lock on `path`, creating the file
    /// when missing. A second live lease on the same path from any process
    /// fails immediately, before DNS binds or routes are touched.
    pub fn acquire(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| anyhow::anyhow!("open writer lock {}: {e}", path.display()))?;
        lock_exclusive(&file).map_err(|e| {
            anyhow::anyhow!(
                "writer lock {} is already held (another Leshy is running): {e}",
                path.display()
            )
        })?;
        Ok(Self { file })
    }

    /// Acquires the lease when a lock path is configured; `None` means the
    /// installation has no fence yet (development configs) and leases
    /// nothing.
    pub fn acquire_optional(path: Option<&Path>) -> anyhow::Result<Option<Self>> {
        match path {
            Some(path) => Ok(Some(Self::acquire(path)?)),
            None => Ok(None),
        }
    }
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        // Explicit symmetric release before the handle closes. Closing the
        // descriptor also releases the OS lock; the explicit call keeps the
        // Windows path readable and the contract obvious.
        let _ = unlock_exclusive(&self.file);
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: flock on a file we own the fd of; LOCK_NB makes contention a
    // visible error instead of a silent hang before startup.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x2;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x1;
    let mut overlapped = windows_sys::Win32::System::IO::OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: Default::default(),
        hEvent: std::ptr::null_mut(),
    };
    // SAFETY: LockFileEx on a file we own the handle of; one byte range is
    // enough, FAIL_IMMEDIATELY turns contention into an error.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn unlock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: unlocking an fd this process holds the lock of.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn unlock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    let mut overlapped = windows_sys::Win32::System::IO::OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: Default::default(),
        hEvent: std::ptr::null_mut(),
    };
    // SAFETY: UnlockFileEx on the same one-byte range we locked.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::UnlockFileEx(
            file.as_raw_handle() as _,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lease_fails_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leshy-writer.lock");
        let first = WriterLease::acquire(&path).unwrap();
        assert!(
            WriterLease::acquire(&path).is_err(),
            "second lease must fail"
        );
        drop(first);
        // The released lock can be taken again.
        let second = WriterLease::acquire(&path).unwrap();
        drop(second);
    }

    #[test]
    fn abandoned_file_content_is_not_authority() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leshy-writer.lock");
        std::fs::write(&path, b"1234\n").unwrap();
        // A leftover file from a dead process must never block a new holder.
        assert!(WriterLease::acquire(&path).is_ok());
    }

    #[test]
    fn optional_lease_is_none_without_path() {
        assert!(WriterLease::acquire_optional(None).unwrap().is_none());
    }
}
