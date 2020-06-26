//! Filesystem APIs implemenation using libc

// Thanks, clippy, but it makes the code cleaner so it's not redundant.
#![allow(clippy::redundant_closure_call)]

use crate::fs::{FileSystem, HostErrno, HostMode, HostOpenFlags, HostStat, IOResult};
use std::{convert::TryFrom, ffi::CString, mem::MaybeUninit};

macro_rules! map_flags {
    ($inflags:ident: $intype:ident -> $resdefault:expr, $($inflag:ident => $outflag:expr,)*) => {{
        let mut flags = $resdefault;

        {
            $(if $inflags & $intype::$inflag == $intype::$inflag {
                flags |= $outflag;
            })*
        }

        flags
    }};
}

impl HostErrno {
    /// Map an errno from `libc` to a cross-platform GDB `HostErrno`.
    pub fn from_libc(errno: libc::c_int) -> Self {
        match errno {
            libc::EPERM => Self::EPERM,
            libc::ENOENT => Self::ENOENT,
            libc::EINTR => Self::EINTR,
            libc::EBADF => Self::EBADF,
            libc::EACCES => Self::EACCES,
            libc::EFAULT => Self::EFAULT,
            libc::EBUSY => Self::EBUSY,
            libc::EEXIST => Self::EEXIST,
            libc::ENODEV => Self::ENODEV,
            libc::ENOTDIR => Self::ENOTDIR,
            libc::EISDIR => Self::EISDIR,
            libc::EINVAL => Self::EINVAL,
            libc::ENFILE => Self::ENFILE,
            libc::EMFILE => Self::EMFILE,
            libc::EFBIG => Self::EFBIG,
            libc::ENOSPC => Self::ENOSPC,
            libc::ESPIPE => Self::ESPIPE,
            libc::EROFS => Self::EROFS,
            libc::ENAMETOOLONG => Self::ENAMETOOLONG,
            _ => Self::EUNKNOWN,
        }
    }
}

impl HostMode {
    /// Map a mode from `libc` to a cross-platform GDB `HostErrno`.
    pub fn from_libc(mode: libc::mode_t) -> Self {
        map_flags! {
            mode: libc -> Self::empty(),
            S_IFREG => Self::S_IFREG,
            S_IFDIR => Self::S_IFDIR,
            S_IRUSR => Self::S_IRUSR,
            S_IWUSR => Self::S_IWUSR,
            S_IXUSR => Self::S_IXUSR,
            S_IRGRP => Self::S_IRGRP,
            S_IWGRP => Self::S_IWGRP,
            S_IXGRP => Self::S_IXGRP,
            S_IROTH => Self::S_IROTH,
            S_IWOTH => Self::S_IWOTH,
            S_IXOTH => Self::S_IXOTH,
        }
    }

    /// Map a mode from a cross-platform GDB `HostErrno` to the native `libc`
    /// type.
    pub fn into_libc(self) -> libc::mode_t {
        map_flags! {
            self: Self -> 0,
            S_IFREG => libc::S_IFREG,
            S_IFDIR => libc::S_IFDIR,
            S_IRUSR => libc::S_IRUSR,
            S_IWUSR => libc::S_IWUSR,
            S_IXUSR => libc::S_IXUSR,
            S_IRGRP => libc::S_IRGRP,
            S_IWGRP => libc::S_IWGRP,
            S_IXGRP => libc::S_IXGRP,
            S_IROTH => libc::S_IROTH,
            S_IWOTH => libc::S_IWOTH,
            S_IXOTH => libc::S_IXOTH,
        }
    }
}

impl HostOpenFlags {
    /// Map flags from `libc` to a cross-platform GDB `HostErrno`.
    pub fn from_libc(flags: libc::c_int) -> Self {
        map_flags! {
            flags: libc -> Self::empty(),
            // No O_RDONLY, it's zero and always set
            O_WRONLY => Self::O_WRONLY,
            O_RDWR   => Self::O_RDWR,
            O_APPEND => Self::O_APPEND,
            O_CREAT  => Self::O_CREAT,
            O_TRUNC  => Self::O_TRUNC,
            O_EXCL   => Self::O_EXCL,
        }
    }

    /// Map flags from a cross-platform GDB `HostErrno` to the native `libc`
    /// type.
    pub fn into_libc(self) -> libc::c_int {
        let mut res = map_flags! {
            self: HostOpenFlags -> 0,
            O_WRONLY => libc::O_WRONLY,
            O_RDWR   => libc::O_RDWR,
            O_APPEND => libc::O_APPEND,
            O_CREAT  => libc::O_CREAT,
            O_TRUNC  => libc::O_TRUNC,
            O_EXCL   => libc::O_EXCL,
        };
        if !self.contains(Self::O_WRONLY) && !self.contains(Self::O_RDWR) {
            res |= libc::O_RDONLY;
        }
        res
    }
}

/// A filesystem implementation that delegates all calls to libc. Basically,
/// this lets you use the operating system's notion of files, which is probably
/// what you want.
#[derive(Debug, Default)]
pub struct LibcFS {
    /// don't initiate this struct outside of this crate, for future backwards
    /// compatibility
    _private: (),
}

fn errno() -> HostErrno {
    HostErrno::from_libc(unsafe { *libc::__errno_location() })
}

impl FileSystem for LibcFS {
    fn host_open(&self, filename: Vec<u8>, flags: HostOpenFlags, mode: HostMode) -> IOResult<u64> {
        Ok((|| {
            let filename = CString::new(filename).map_err(|_| HostErrno::ENOENT)?;

            let fd: libc::c_int =
                unsafe { libc::open(filename.as_ptr(), flags.into_libc(), mode.into_libc()) };
            if fd >= 0 {
                Ok(u64::from(fd as u32))
            } else {
                Err(errno())
            }
        })())
    }
    fn host_close(&self, fd: u64) -> IOResult<()> {
        Ok((|| {
            if unsafe { libc::close(fd as libc::c_int) } == 0 {
                Ok(())
            } else {
                Err(errno())
            }
        })())
    }
    fn host_pread(&self, fd: u64, count: u64, offset: u64) -> IOResult<Vec<u8>> {
        Ok((|| {
            // Allocate `count` (converted to usize) bytes
            let count = usize::try_from(count).unwrap_or(std::usize::MAX);
            let mut buf: Vec<u8> = Vec::with_capacity(count);

            // Fill bytes as many as `read` bytes
            let read: isize = unsafe {
                libc::pread(
                    fd as libc::c_int,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    count,
                    offset as libc::off_t,
                )
            };

            if read >= 0 {
                // Mark bytes up to `read` as initiated
                unsafe {
                    buf.set_len(read as usize);
                }
                Ok(buf)
            } else {
                Err(errno())
            }
        })())
    }
    fn host_pwrite(&self, fd: u64, offset: u64, data: Vec<u8>) -> IOResult<u64> {
        Ok((|| {
            // Write data, as much as `written` bytes of data
            let written: isize = unsafe {
                libc::pwrite(
                    fd as libc::c_int,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    offset as libc::off_t,
                )
            };

            if written >= 0 {
                Ok(written as u64)
            } else {
                Err(errno())
            }
        })())
    }
    fn host_fstat(&self, fd: u64) -> IOResult<HostStat> {
        Ok((|| {
            let mut stat: MaybeUninit<libc::stat> = MaybeUninit::uninit();

            if unsafe { libc::fstat(fd as libc::c_int, stat.as_mut_ptr()) } == 0 {
                let stat = unsafe { stat.assume_init() };
                Ok(HostStat {
                    // libc's st_dev is different than GDB's st_dev.
                    // st_dev in GDB is described by https://sourceware.org/gdb/onlinedocs/gdb/struct-stat.html#struct-stat:
                    // "A value of 0 represents a file, 1 the console."
                    // While libc's ID is more complex (see `man fstat`)
                    st_dev: 0,

                    st_ino: stat.st_ino as _,
                    st_mode: HostMode::from_libc(stat.st_mode),
                    st_nlink: stat.st_nlink as _,
                    st_uid: stat.st_uid as _,
                    st_gid: stat.st_gid as _,
                    st_rdev: stat.st_rdev as _,
                    st_size: stat.st_size as _,
                    st_blksize: stat.st_blksize as _,
                    st_blocks: stat.st_blocks as _,
                    st_atime: stat.st_atime as _,
                    st_mtime: stat.st_mtime as _,
                    st_ctime: stat.st_ctime as _,
                })
            } else {
                Err(errno())
            }
        })())
    }
    fn host_unlink(&self, _filename: Vec<u8>) -> IOResult<()> {
        Err(())
    }
    fn host_readlink(&self, _filename: Vec<u8>) -> IOResult<Vec<u8>> {
        Err(())
    }
    fn host_setfs(&self, _pid: u64) -> IOResult<()> {
        Err(())
    }
}
