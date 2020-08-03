//! Filesystem APIs implemenation using libc

use crate::fs::{FileSystem, HostErrno, HostMode, HostOpenFlags, HostStat, IOResult};
use std::{convert::TryFrom, ffi::CString, mem::MaybeUninit};

/// A filesystem implementation that delegates all calls to libc. Basically,
/// this lets you use the operating system's notion of files, which is probably
/// what you want.
#[derive(Debug, Default)]
pub struct LibcFS {
    /// don't initiate this struct outside of this crate, for future backwards
    /// compatibility
    _private: (),
}

macro_rules! map_flags {
    ($inflags:ident: $intype:ident, $($inflag:ident => $outflag:expr,)*) => {{
        let mut flags = 0;

        {
            $(if $inflags & $intype::$inflag == $intype::$inflag {
                flags |= $outflag;
            })*
        }

        flags
    }};
}

fn errno() -> HostErrno {
    match unsafe { *libc::__errno_location() } {
        libc::EPERM => HostErrno::EPERM,
        libc::ENOENT => HostErrno::ENOENT,
        libc::EINTR => HostErrno::EINTR,
        libc::EBADF => HostErrno::EBADF,
        libc::EACCES => HostErrno::EACCES,
        libc::EFAULT => HostErrno::EFAULT,
        libc::EBUSY => HostErrno::EBUSY,
        libc::EEXIST => HostErrno::EEXIST,
        libc::ENODEV => HostErrno::ENODEV,
        libc::ENOTDIR => HostErrno::ENOTDIR,
        libc::EISDIR => HostErrno::EISDIR,
        libc::EINVAL => HostErrno::EINVAL,
        libc::ENFILE => HostErrno::ENFILE,
        libc::EMFILE => HostErrno::EMFILE,
        libc::EFBIG => HostErrno::EFBIG,
        libc::ENOSPC => HostErrno::ENOSPC,
        libc::ESPIPE => HostErrno::ESPIPE,
        libc::EROFS => HostErrno::EROFS,
        libc::ENAMETOOLONG => HostErrno::ENAMETOOLONG,
        _ => HostErrno::EUNKNOWN,
    }
}

impl FileSystem for LibcFS {
    fn host_open(
        &self,
        filename: Vec<u8>,
        gdbflags: HostOpenFlags,
        gdbmode: HostMode,
    ) -> IOResult<u64> {
        Ok((|| {
            let filename = CString::new(filename).map_err(|_| HostErrno::ENOENT)?;

            let flags = map_flags! {
                gdbflags: HostOpenFlags,
                O_RDONLY => libc::O_RDONLY,
                O_WRONLY => libc::O_WRONLY,
                O_RDWR   => libc::O_RDWR,
                O_APPEND => libc::O_APPEND,
                O_CREAT  => libc::O_CREAT,
                O_TRUNC  => libc::O_TRUNC,
                O_EXCL   => libc::O_EXCL,
            };

            let mode = map_flags! {
                gdbmode: HostMode,
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
            };

            let fd: libc::c_int = unsafe { libc::open(filename.as_ptr(), flags, mode) };
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
                    st_dev: stat.st_dev as _,
                    st_ino: stat.st_ino as _,
                    st_mode: stat.st_mode as _,
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
