use crate::{
    bindings::{self},
    c::{self, MapErrNo as _, ProcessInfo},
    err_exit,
    sys::CrossStat,
    warnx,
};
use libc::{c_int, c_uint};
use std::{
    fs,
    io::{self, Read as _},
    os::unix::fs::OpenOptionsExt as _,
};

pub const UID_MAX: libc::uid_t = 65535;
pub const GID_MAX: libc::gid_t = 65535;
pub const BOOT_TIME: libc::clockid_t = libc::CLOCK_BOOTTIME;

impl CrossStat for bindings::stat {
    fn st_atime(&self) -> bindings::timespec {
        self.st_atim
    }
    fn st_mtime(&self) -> bindings::timespec {
        self.st_mtim
    }
}

pub fn random_index(len: u32) -> u32 {
    let range = u32::MAX - (u32::MAX % len);
    loop {
        let random = getrandom();
        if random < range {
            return random % len;
        }
    }
}

fn getrandom() -> u32 {
    let mut buf = [0u8; 4];
    let res = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut _, size_of_val(&buf), 0) };
    if res == -1 || res != buf.len() as isize {
        err_exit!("getrandom");
    }
    u32::from_ne_bytes(buf)
}

pub fn get_proc_info() -> Result<ProcessInfo, ()> {
    let ppid = c::getppid();
    let sid = c::getsid(0)?;
    let path = format!("/proc/{}/stat", ppid);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| warnx!("failed to open {}: {e}", path))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| warnx!("read {path}: {e}"))?;
    let (tty, start_time) = parse_stat_file(&content)?;

    Ok(ProcessInfo {
        ppid,
        sid,
        start_time,
        tty,
    })
}

/// - returns (tty, start_time)
fn parse_stat_file(content: &str) -> Result<(u32, u64), ()> {
    // Get the 7th field, 5 fields after the last ')',
    // (2nd field) because the 2nd field 'comm' can include
    // spaces and closing paranthesis too.
    // See https://www.sudo.ws/alerts/linux_tty.html
    let (_, after) = content
        .rsplit_once(") ")
        .ok_or_else(|| warnx!("can not parse stat file"))?;
    let mut fields = after.split(' ');
    // 2 + 5 = 7
    // 0 1 2 3 4
    let tty = fields
        .nth(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| warnx!("can not parse tty num"))?;
    // 7 + 15 = 22
    // 0 1 2 .. 14
    let starttime = fields
        .nth(14)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| warnx!("can not parse start time"))?;
    Ok((tty, starttime))
}

#[test]
fn parse_stat() {
    let content = "12437 (doas ( ) )) S 12309 12437 12309 34820 12437 4194560 556 0 0 0 31 54 0 0 20 0 2 0 247401 398000128 2592 18446744073709551615 1 1 0 0 0 0 0 0 134876794 0 0 0 17 6 0 0 0 0 0 0 0 0 0 0 0 0 0";
    let (tty, starttime) = parse_stat_file(content).unwrap();
    assert_eq!(tty, 34820);
    assert_eq!(starttime, 247401);
}

pub fn closefrom(low: c_int) -> io::Result<()> {
    unsafe {
        libc::close_range(
            low as c_uint,
            c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC as c_int,
        )
        .map(io::Error::last_os_error)
    }
}
