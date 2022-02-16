// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::{self, File};
use std::io::{Error, ErrorKind, Result};
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::{open_by_path, safe_join};

/// Safe version of `PathBuf` to protect from TOCTOU style of attacks.
///
/// There's a race window for attackers between time to validate a path and time to use the path.
/// An attacker may maliciously change the path by symlinks to compose an attack.
///
/// The `/proc/self/fd/xxx` on linux is a symlink to the real target corresponding to the process's
/// file descriptor `xxx`. And the symlink will be kept stable until the file descriptor has been
/// closed. Combined with `O_PATH`, we could build a safe version of `PathBuf` by:
/// - Generate a safe path from `root` and `path` by using [crate::safe_join()].
/// - Open the safe path with O_PATH | O_CLOEXEC flags, say it's assigned `fd_num`.
/// - Read the symlink target of `/proc/self/fd/fd_num`.
/// - Compare the symlink target with the safe path, it's safe if these two paths equal.
/// - Use the symlink target as a safe PathBuf.
/// - Close the `fd_num` when dropping the `SafePathBuf` object.
#[derive(Debug)]
pub struct SafePathBuf {
    file: File,
    path: PathBuf,
    target: PathBuf,
}

impl SafePathBuf {
    /// Create a `SafePathBuf` from the `root` and an unsafe `path`.
    ///
    /// The `path` must be a subdirectory of `root`, otherwise error will be returned.
    pub fn new<R: AsRef<Path>, U: AsRef<Path>>(root: R, path: U) -> Result<Self> {
        let safe_path = safe_join(root, path)?;
        Self::from_path(safe_path)
    }

    /// Create a `SafePathBuf` from an path.
    ///
    /// If the resolved value of `path` doesn't equal to `path`, an error will be returned.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = open_by_path(path.as_ref())?;
        let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        let link_path = fs::read_link(&proc_path)?;

        if link_path.as_path() != path.as_ref() {
            Err(Error::new(
                ErrorKind::Other,
                format!(
                    "The target path changes from {} to {} underneath, possible under attacking!!!",
                    path.as_ref().display(),
                    link_path.display()
                ),
            ))
        } else {
            Ok(SafePathBuf {
                file,
                path: PathBuf::from(proc_path),
                target: link_path,
            })
        }
    }

    /// Get the real target path.
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Check whether the target path is a directory.
    pub fn is_dir(&self) -> bool {
        self.target.is_dir()
    }
}

impl Deref for SafePathBuf {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for SafePathBuf {
    fn as_ref(&self) -> &Path {
        self.path.as_path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_safe_path_buf() {
        let rootfs_dir = tempfile::tempdir().expect("failed to create tmpdir");
        let rootfs_path = rootfs_dir.path();

        fs::create_dir(rootfs_path.join("symlink_dir")).unwrap();
        symlink("/endpoint", rootfs_path.join("symlink_dir/endpoint")).unwrap();
        fs::write(rootfs_path.join("endpoint"), "test").unwrap();
        let path = SafePathBuf::new(rootfs_path, "symlink_dir/endpoint").unwrap();
        let link = fs::read_link(&path).unwrap();
        assert_eq!(link, rootfs_path.join("endpoint"));
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(&content, "test");

        let path = SafePathBuf::from_path(rootfs_path.join("endpoint")).unwrap();
        let link = fs::read_link(&path).unwrap();
        assert_eq!(link, rootfs_path.join("endpoint"));
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(&content, "test");
    }

    #[test]
    fn test_safe_path_race() {
        let root_dir = tempfile::tempdir().expect("failed to create tmpdir");
        let root_path = root_dir.path();
        let root_path2 = root_path.to_path_buf();
        let barrier = Arc::new(Barrier::new(2));
        let barrier2 = barrier.clone();

        fs::write(root_path.join("a"), "a".as_bytes()).unwrap();
        fs::write(root_path.join("b"), "b".as_bytes()).unwrap();
        fs::write(root_path.join("c"), "c".as_bytes()).unwrap();
        symlink("a", root_path.join("s")).unwrap();

        let thread = thread::spawn(move || {
            // step 1
            barrier2.wait();
            fs::remove_file(root_path2.join("a")).unwrap();
            symlink("b", root_path2.join("a")).unwrap();
            barrier2.wait();

            // step 2
            barrier2.wait();
            fs::remove_file(root_path2.join("b")).unwrap();
            symlink("c", root_path2.join("b")).unwrap();
            barrier2.wait();
        });

        let path = safe_join(&root_path, "s").unwrap();
        let data = fs::read_to_string(&path).unwrap();
        assert_eq!(&data, "a");
        assert!(path.is_file());
        barrier.wait();
        barrier.wait();
        // Verify the target has been silently redirected.
        let data = fs::read_to_string(&path).unwrap();
        assert_eq!(&data, "b");
        SafePathBuf::from_path(&path).unwrap_err();

        let path = safe_join(&root_path, "s").unwrap();
        let safe_path = SafePathBuf::from_path(&path).unwrap();
        let data = fs::read_to_string(&safe_path).unwrap();
        assert_eq!(&data, "b");

        // step2
        barrier.wait();
        barrier.wait();
        // Verify it still points to the old target.
        let data = fs::read_to_string(&safe_path).unwrap();
        assert_eq!(&data, "b");

        thread.join().unwrap();
    }
}
