use crate::bindings::{self};
use crate::c::{MapErrNo as _, ProcessInfo};
use crate::sys::CrossStat;
use crate::{c, err, errx};
use libc::c_int;
use std::{fs, io, mem};

pub const BOOT_TIME: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;

pub const UID_MAX: libc::uid_t = bindings::UID_MAX;
pub const GID_MAX: libc::gid_t = bindings::GID_MAX;

impl CrossStat for bindings::stat {
    fn st_atime(&self) -> bindings::timespec {
        self.st_atimespec
    }
    fn st_mtime(&self) -> bindings::timespec {
        self.st_mtimespec
    }
}

pub fn random_index(len: u32) -> u32 {
    unsafe { libc::arc4random_uniform(len) }
}

pub fn get_proc_info() -> Result<ProcessInfo, ()> {
    use libc::proc_bsdinfo;
    let ppid = c::getppid();
    let sid = c::getsid(0)?;
    let info = unsafe {
        let mut info: proc_bsdinfo = mem::zeroed();
        let res = bindings::proc_pidinfo(
            ppid,
            bindings::PROC_PIDTBSDINFO as i32,
            0,
            &raw mut info as _,
            size_of_val(&info) as c_int,
        );
        if res == -1 {
            err!("get proc info");
        }
        info
    };
    let start_time = info.pbi_start_tvsec;
    let tty = info.e_tdev;
    if start_time == 0 || tty == 0 {
        errx!("get proc info");
    }
    Ok(ProcessInfo {
        ppid,
        sid,
        tty,
        start_time,
    })
}

pub fn closefrom(low: c_int) -> io::Result<()> {
    // dir "." and ".." is skipped
    let entries = fs::read_dir("/dev/fd")?;
    for entry in entries {
        let entry = entry?;
        let filename = entry.file_name();
        let fd = filename
            .to_str()
            .and_then(|s| s.parse::<c_int>().ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "file name is not an integer")
            })?;
        if fd < low {
            continue;
        }
        // Only set CLOEXEC to avoid potential libdispatch crash when we close its fds.
        // It also prevents closing the dir fd.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC).map(io::Error::last_os_error)?;
        }
    }
    Ok(())
}
