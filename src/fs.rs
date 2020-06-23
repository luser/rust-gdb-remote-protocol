//! Filesystem APIs for GDB, vFile

use bitflags::bitflags;
use std::{
    convert::TryFrom,
    ffi::CString,
    io::{self, prelude::*},
    mem::MaybeUninit,
};

/// Errno values for Host I/O operations.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum HostErrno {
    EPERM = 1,
    ENOENT = 2,
    EINTR = 4,
    EBADF = 9,
    EACCES = 13,
    EFAULT = 14,
    EBUSY = 16,
    EEXIST = 17,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    ENAMETOOLONG = 91,
    EUNKNOWN = 9999,
}

/// The result type for host I/O operations.  Return error if the operation
/// in question is not implemented.  Otherwise, the success type indicates
/// whether the operation succeeded, with `HostErrno` values for failure.
pub type IOResult<T> = Result<Result<T, HostErrno>, ()>;

bitflags! {
    /// Host file permissions.
    pub struct HostMode: u32 {
        /// A regular file.
        const S_IFREG = 0o100000;
        /// A directory.
        const S_IFDIR = 0o40000;
        /// User read permissions.
        const S_IRUSR = 0o400;
        /// User write permissions.
        const S_IWUSR = 0o200;
        /// User execute permissions.
        const S_IXUSR = 0o100;
        /// Group read permissions.
        const S_IRGRP = 0o40;
        /// Group write permissions
        const S_IWGRP = 0o20;
        /// Group execute permissions.
        const S_IXGRP = 0o10;
        /// World read permissions.
        const S_IROTH = 0o4;
        /// World write permissions
        const S_IWOTH = 0o2;
        /// World execute permissions.
        const S_IXOTH = 0o1;
    }
}

bitflags! {
    // The read/write flags below may look a little weird, but that is the way
    // they are defined in the protocol.
    /// Host flags for opening files.
    pub struct HostOpenFlags: u32 {
        /// A read-only file.
        const O_RDONLY = 0x0;
        /// A write-only file.
        const O_WRONLY = 0x1;
        /// A read-write file.
        const O_RDWR = 0x2;
        /// Append to an existing file.
        const O_APPEND = 0x8;
        /// Create a non-existent file.
        const O_CREAT = 0x200;
        /// Truncate an existing file.
        const O_TRUNC = 0x400;
        /// Exclusive access.
        const O_EXCL = 0x800;
    }
}

/// Data returned by a host fstat request.  The members of this structure are
/// specified by the remote protocol; conversion of actual host stat
/// information into this structure may therefore require truncation of some
/// members.
#[derive(Debug)]
pub struct HostStat {
    /// The device.
    pub st_dev: u32,
    /// The inode.
    pub st_ino: u32,
    /// Protection bits.
    pub st_mode: u32,
    /// The number of hard links.
    pub st_nlink: u32,
    /// The user id of the owner.
    pub st_uid: u32,
    /// The group id of the owner.
    pub st_gid: u32,
    /// The device type, if an inode device.
    pub st_rdev: u32,
    /// The size of the file in bytes.
    pub st_size: u64,
    /// The blocksize for the filesystem.
    pub st_blksize: u64,
    /// The number of blocks allocated.
    pub st_blocks: u64,
    /// The last time the file was accessed, in seconds since the epoch.
    pub st_atime: u32,
    /// The last time the file was modified, in seconds since the epoch.
    pub st_mtime: u32,
    /// The last time the file was changed, in seconds since the epoch.
    pub st_ctime: u32,
}

// Having to write out all the fields for these two operations is annoying,
// but the alternatives are even more annoying.  For instance, we could
// represent HostStat as a big array, with fields at appropriate offsets, but
// we'd have to write a bunch of accessor methods.  Note that #[repr(C)]
// isn't quite good enough, since that might introduce C-mandated padding
// into the structure.
pub fn write_stat<W>(writer: &mut W, stat: HostStat) -> io::Result<()>
where
    W: Write,
{
    use byteorder::{BigEndian, WriteBytesExt};

    writer.write_u32::<BigEndian>(stat.st_dev)?;
    writer.write_u32::<BigEndian>(stat.st_ino)?;
    writer.write_u32::<BigEndian>(stat.st_mode)?;
    writer.write_u32::<BigEndian>(stat.st_nlink)?;
    writer.write_u32::<BigEndian>(stat.st_uid)?;
    writer.write_u32::<BigEndian>(stat.st_gid)?;
    writer.write_u32::<BigEndian>(stat.st_rdev)?;
    writer.write_u64::<BigEndian>(stat.st_size)?;
    writer.write_u64::<BigEndian>(stat.st_blksize)?;
    writer.write_u64::<BigEndian>(stat.st_blocks)?;
    writer.write_u32::<BigEndian>(stat.st_atime)?;
    writer.write_u32::<BigEndian>(stat.st_mtime)?;
    writer.write_u32::<BigEndian>(stat.st_ctime)
}

#[allow(dead_code)]
pub fn read_stat(v: &[u8]) -> io::Result<HostStat> {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Cursor;

    let mut r = Cursor::new(v);
    let st_dev = r.read_u32::<BigEndian>()?;
    let st_ino = r.read_u32::<BigEndian>()?;
    let st_mode = r.read_u32::<BigEndian>()?;
    let st_nlink = r.read_u32::<BigEndian>()?;
    let st_uid = r.read_u32::<BigEndian>()?;
    let st_gid = r.read_u32::<BigEndian>()?;
    let st_rdev = r.read_u32::<BigEndian>()?;
    let st_size = r.read_u64::<BigEndian>()?;
    let st_blksize = r.read_u64::<BigEndian>()?;
    let st_blocks = r.read_u64::<BigEndian>()?;
    let st_atime = r.read_u32::<BigEndian>()?;
    let st_mtime = r.read_u32::<BigEndian>()?;
    let st_ctime = r.read_u32::<BigEndian>()?;

    Ok(HostStat{ st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, st_rdev,
                 st_size, st_blksize, st_blocks, st_atime, st_mtime, st_ctime })
}

/// TODO: doc
pub trait FileSystem {
    /// Open a file on the remote stub's current filesystem.
    fn host_open(&self, _filename: Vec<u8>, _flags: HostOpenFlags, _mode: HostMode) -> IOResult<u64> {
        Err(())
    }

    /// Close a file opened with `host_open`.
    fn host_close(&self, _fd: u64) -> IOResult<()> {
        Err(())
    }

    /// Read data from an open file at the given offset.
    fn host_pread(&self, _fd: u64, _count: u64, _offset: u64) -> IOResult<Vec<u8>> {
        Err(())
    }

    /// Write data to an open file at the given offset.
    fn host_pwrite(&self, _fd: u64, _offset: u64, _data: Vec<u8>) -> IOResult<u64> {
        Err(())
    }

    /// Return a `HostStat` describing the attributes of the given open file.
    fn host_fstat(&self, _fd: u64) -> IOResult<HostStat> {
        Err(())
    }

    /// Remove a file from the remote stub's current filesystem.
    fn host_unlink(&self, _filename: Vec<u8>) -> IOResult<()> {
        Err(())
    }

    /// Read the contents of a symbolic link on the remote stub's current filesystem.
    fn host_readlink(&self, _filename: Vec<u8>) -> IOResult<Vec<u8>> {
        Err(())
    }

    /// Set the current filesystem for subsequent host I/O requests.  If the
    /// given pid is 0, select the filesystem of the remote stub.  Otherwise,
    /// select the filesystem as seen by the process with the given pid.
    fn host_setfs(&self, _pid: u64) -> IOResult<()> {
        Err(())
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
    fn host_open(&self, filename: Vec<u8>, gdbflags: HostOpenFlags, gdbmode: HostMode) -> IOResult<u64> {
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
