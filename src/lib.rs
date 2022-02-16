// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! A library to safely handle filesystem paths, typically for container runtimes.
//!
//! Linux [mount namespace](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
//! provides isolation of the list of mounts seen by the processes in each
//! [namespace](https://man7.org/linux/man-pages/man7/namespaces.7.html) instance.
//! Thus, the processes in each of the mount namespace instances will see distinct single-directory
//! hierarchies.
//!
//! Containers are used to isolate workloads from the host system. Container on Linux systems
//! depends on the mount namespace to build an isolated root filesystem for each container,
//! thus protect the host and containers from each other. When creating containers, the container
//! runtime needs to setup filesystem mounts for container rootfs/volumes. Configuration for
//! mounts/paths may be indirectly controlled by end users through:
//! - container images
//! - Kubernetes pod specifications
//! - hook command line arguments
//!
//! These volume configuration information may be controlled by end users/malicious attackers,
//! so it must not be trusted by container runtimes. When the container runtime is preparing mount
//! namespace for a container, it must be very careful to validate user input configuration
//! information and ensure data out of the container rootfs directory won't be affected
//! by the container. There are several types of attacks related to container mount namespace:
//! - symlink based attack
//! - Time of check to time of use(TOCTTOU)
//!
//! This crate provides several mechanisms for container runtimes to safely handle filesystem paths
//! when preparing mount namespace for containers.
//! - [safe_join](crate::safe_join()): safely join `unsafe_path` to `root`, and ensure `unsafe_path`
//!   is scoped under `root`.
//! - [scoped_resolve](crate::scoped_resolve()): resolve `unsafe_path` to a relative path, rooted
//!   at and constrained by `root`.
//! - [SafePathBuf](crate::SafePathBuf): safe version of `PathBuf` to protect from TOCTOU style
//!   of attacks.
//! - [SafeDirBuilder](crate::SafeDirBuilder): safe version of `DirBuilder` to protect from TOCTOU
//!   style of attacks.

#![deny(missing_docs)]
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

mod safe_dir_builder;
pub use safe_dir_builder::SafeDirBuilder;

mod safe_join;
pub use safe_join::{safe_join, scoped_resolve};

mod safe_path_buf;
pub use safe_path_buf::SafePathBuf;

/// Open a direcoty/path by path.
fn open_by_path<P: AsRef<Path>>(path: P) -> std::io::Result<File> {
    let o_flags = libc::O_PATH | libc::O_CLOEXEC;

    OpenOptions::new()
        .read(true)
        .custom_flags(o_flags)
        .open(path.as_ref())
}
