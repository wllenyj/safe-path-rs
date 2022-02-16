// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::DirBuilder;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::{safe_join, SafePathBuf};

const DIRECTORY_MODE_DEFAULT: u32 = 0o700;
const DIRECTORY_MODE_MASK: u32 = 0o777;

/// Safe version of `DirBuilder` to protect from TOCTOU style of attacks.
#[derive(Debug)]
pub struct SafeDirBuilder {
    root: PathBuf,
    mode: u32,
    recursive: bool,
}

impl SafeDirBuilder {
    /// Creates a new set of options with default mode/security settings for all platforms and
    /// also non-recursive.
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root = root.as_ref().canonicalize()?;
        if !root.is_dir() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Invalid path: {}", root.display()),
            ));
        }

        Ok(SafeDirBuilder {
            root,
            mode: DIRECTORY_MODE_DEFAULT,
            recursive: false,
        })
    }

    /// Indicates that directories should be created recursively, creating all parent directories.
    ///
    /// Parents that do not exist are created with the same security and permissions settings.
    pub fn recursive(&mut self) -> &mut Self {
        self.recursive = true;
        self
    }

    /// Sets the mode to create new directories with. This option defaults to 0o755.
    pub fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = mode & DIRECTORY_MODE_MASK;
        self
    }

    /// Creates the specified directory with the options configured in this builder.
    ///
    /// The `path` must be a subdirectory of `SafePathBuf::root()`, otherwise error will be returned.
    /// It is considered an error if the directory already exists unless recursive mode is enabled.
    pub fn create<P: AsRef<Path>>(&self, path: P) -> Result<SafePathBuf> {
        let mut root = self.root.clone();
        let path = safe_join("/", path)?;
        let mut suffix = path.strip_prefix(&root).map_err(|_| {
            Error::new(
                ErrorKind::Other,
                format!("Invalid path: {}", path.display()),
            )
        })?;
        if suffix.file_name().is_none() {
            return SafePathBuf::from_path(root);
        }
        if !self.recursive {
            if let Some(parent) = path.parent() {
                root = root.join(parent);
            }
            // Safe to unwrap() because we have verified `suffix` is not empty.
            suffix = Path::new(suffix.file_name().unwrap());
        }

        for comp in suffix {
            let file = SafePathBuf::from_path(&root)?;
            if !file.target().is_dir() {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Invalid path: {}", root.display()),
                ));
            }
            root = root.join(comp);
            DirBuilder::new()
                .mode(self.mode)
                .recursive(true)
                .create(&root)?;
        }

        let result = SafePathBuf::from_path(&root)?;
        if !result.target().is_dir() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Invalid path: {}", root.display()),
            ));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn test_safe_dir_builder() {
        let rootfs_dir = tempfile::tempdir().expect("failed to create tmpdir");
        let rootfs_path = rootfs_dir.path();

        SafeDirBuilder::new(rootfs_path.join("__does_not_exist__")).unwrap_err();

        fs::write(rootfs_path.join("txt"), "test").unwrap();
        SafeDirBuilder::new(rootfs_path.join("txt")).unwrap_err();

        let mut builder = SafeDirBuilder::new(&rootfs_path).unwrap();
        println!("{:?}", builder);
        builder.create("/txt/a").unwrap_err();

        let path = builder.create(rootfs_path.join(".")).unwrap();
        assert_eq!(path.target(), rootfs_path);
        builder.create(rootfs_path.join("a/b")).unwrap_err();
        builder.create(rootfs_path.join("a/b/c")).unwrap_err();
        builder.create(rootfs_path.join("txt")).unwrap_err();

        let path = builder.create(rootfs_path.join("a")).unwrap();
        assert_eq!(path.target(), rootfs_path.join("a"));
        assert!(rootfs_path.join("a").is_dir());

        builder.recursive();
        builder.mode(0o740);
        let path = builder.create(rootfs_path.join("a/b/c/d")).unwrap();
        assert_eq!(path.target(), rootfs_path.join("a/b/c/d"));
        assert!(rootfs_path.join("a/b/c/d").is_dir());

        builder.create(rootfs_path.join("txt/e/f")).unwrap_err();

        fs::write(rootfs_path.join("a/b/txt"), "test").unwrap();
        builder.create(rootfs_path.join("a/b/txt/h/i")).unwrap_err();

        assert_eq!(
            rootfs_path.join("a").metadata().unwrap().mode() & 0o777,
            DIRECTORY_MODE_DEFAULT,
        );
        assert_eq!(
            rootfs_path.join("a/b").metadata().unwrap().mode() & 0o777,
            0o740
        );
        assert_eq!(
            rootfs_path.join("a/b/c").metadata().unwrap().mode() & 0o777,
            0o740
        );
        assert_eq!(
            rootfs_path.join("a/b/c/d").metadata().unwrap().mode() & 0o777,
            0o740
        );
    }
}
