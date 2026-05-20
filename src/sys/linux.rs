use crate::{
    bindings::{self},
    c::ProcessInfo,
    err_exit,
    sys::CrossStat,
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
    todo!()
}
