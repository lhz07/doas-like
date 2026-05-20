use crate::{
    SAFE_PATH,
    bindings::{self, pam_handle_t},
    config::{Config, Env, Val},
    err, errx, sys,
    timestamp::Time,
    utils::selfref::{OwnedRef, SelfRef},
    warn, warnx,
};
use libc::{c_char, c_int, clockid_t, gid_t, pid_t, uid_t};
use std::{
    collections::HashMap,
    env,
    ffi::{CStr, CString, OsStr, OsString, c_void},
    io::{self, Write as _},
    mem,
    os::{
        fd::{AsRawFd as _, BorrowedFd},
        unix::ffi::OsStrExt as _,
    },
    ptr::NonNull,
};

// very simple bindings -------------------------------------------

pub fn getuid() -> uid_t {
    unsafe { libc::getuid() }
}

pub fn getgid() -> gid_t {
    unsafe { libc::getgid() }
}

pub fn geteuid() -> uid_t {
    unsafe { libc::geteuid() }
}

pub fn getpid() -> pid_t {
    unsafe { libc::getpid() }
}

pub fn getppid() -> pid_t {
    unsafe { libc::getppid() }
}

// very simple bindings -------------------------------------------

pub fn setprogname(name: &CStr) {
    #[cfg(target_os = "macos")]
    unsafe {
        libc::setprogname(name.as_ptr());
    }
    let _ = name;
}

pub fn setuid(uid: uid_t) -> Result<(), ()> {
    unsafe { libc::setuid(uid).map(|| warn!("setuid")) }
}

pub fn seteuid(uid: uid_t) -> Result<(), ()> {
    unsafe { libc::seteuid(uid).map(|| warn!("seteuid")) }
}

pub fn setreuid(ruid: uid_t, euid: uid_t) -> Result<(), ()> {
    unsafe { libc::setreuid(ruid, euid).map(|| warn!("setreuid")) }
}

pub fn setregid(rgid: uid_t, egid: uid_t) -> Result<(), ()> {
    unsafe { libc::setregid(rgid, egid).map(|| warn!("setregid")) }
}

/// # Safety
/// `str` must be a valid pointer.
pub unsafe fn strdup(str: *const c_char) -> NonNull<c_char> {
    let str = unsafe { libc::strdup(str) };
    let str = NonNull::new(str);
    match str {
        Some(str) => str,
        None => {
            warn!("could not allocate str");
            std::process::exit(1);
        }
    }
}

pub fn calloc(n: usize, size: usize) -> NonNull<c_void> {
    unsafe {
        let data = libc::calloc(n, size);
        let data = NonNull::new(data);
        match data {
            Some(data) => data,
            None => {
                warn!("could not allocate memory for n: {}, size: {}", n, size);
                std::process::exit(1);
            }
        }
    }
}

pub fn getgroups() -> Result<Vec<gid_t>, ()> {
    use bindings::NGROUPS_MAX;
    // on macOS, NGROUPS_MAX is 16, while on Linux,
    // NGROUPS_MAX is 65536, that's too big for a stack array.
    // So we use stack array temporarily, then copy it to a Vec.
    unsafe {
        let mut groups = [0; NGROUPS_MAX as usize];
        let ngroups = libc::getgroups(NGROUPS_MAX as i32, groups.as_mut_ptr());
        if ngroups == -1 {
            err!("getgroups");
        }
        let ngroups = ngroups as usize;
        let mut vec = Vec::with_capacity(ngroups + 1);
        vec.extend(&groups[..ngroups]);
        Ok(vec)
    }
}

pub fn get_terminal_attr(fd: BorrowedFd<'_>) -> io::Result<libc::termios> {
    unsafe {
        let mut termios = mem::zeroed();
        libc::tcgetattr(fd.as_raw_fd(), &mut termios).map(io::Error::last_os_error)?;
        Ok(termios)
    }
}

pub fn set_terminal_attr(fd: BorrowedFd<'_>, termios: &libc::termios) -> io::Result<()> {
    unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, termios).map(io::Error::last_os_error) }
}

pub fn cfmakeraw(termios: &mut libc::termios) {
    unsafe {
        libc::cfmakeraw(termios);
    }
}

pub fn gethostname() -> io::Result<CString> {
    let mut buf = [0; libc::_SC_HOST_NAME_MAX as usize + 1];
    unsafe {
        libc::gethostname(buf.as_mut_ptr(), size_of_val(&buf)).map(io::Error::last_os_error)?;
        let s = CStr::from_ptr(buf.as_ptr()).to_owned();
        Ok(s)
    }
}

#[cfg(not(target_os = "macos"))]
pub fn get_all_groups() -> Result<Vec<gid_t>, ()> {
    let mut groups = getgroups()?;
    groups.push(getgid());
    Ok(groups)
}

pub fn random_index(len: u32) -> u32 {
    sys::random_index(len)
}

pub struct Passwd {
    pub pw_name: OwnedRef<CStr>,
    pub pw_passwd: OwnedRef<CStr>,
    pub pw_uid: uid_t,
    pub pw_gid: gid_t,
    pub pw_gecos: OwnedRef<CStr>,
    pub pw_dir: OwnedRef<CStr>,
    pub pw_shell: OwnedRef<CStr>,
}

impl Passwd {
    unsafe fn new(passwd: *const libc::passwd) -> Self {
        unsafe {
            Self {
                pw_name: OwnedRef::new(CStr::from_ptr((*passwd).pw_name)),
                pw_passwd: OwnedRef::new(CStr::from_ptr((*passwd).pw_passwd)),
                pw_uid: (*passwd).pw_uid,
                pw_gid: (*passwd).pw_gid,
                pw_gecos: OwnedRef::new(CStr::from_ptr((*passwd).pw_gecos)),
                pw_dir: OwnedRef::new(CStr::from_ptr((*passwd).pw_dir)),
                pw_shell: OwnedRef::new(CStr::from_ptr((*passwd).pw_shell)),
            }
        }
    }
}

pub fn getpwuid(uid: uid_t) -> Result<SelfRef<Passwd, Vec<c_char>>, ()> {
    let mut pwd = unsafe { mem::zeroed() };
    let mut result = std::ptr::null_mut();

    let pwsz = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let buflen = if pwsz > 0 { pwsz } else { 1024 };
    let mut buf = vec![0; buflen as usize];
    loop {
        let rv = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut result,
            )
        };
        if rv == 0 {
            break;
        } else if rv == libc::ERANGE {
            let new_size = buf
                .len()
                .checked_mul(2)
                .ok_or_else(|| warnx!("getpwuid: buf size overflow"))?;
            buf.resize(new_size, 0);
        } else {
            err!("getpwuid");
        }
    }
    if result.is_null() {
        errx!("no passwd entry for uid {uid}");
    }

    // we have checked result is not null
    let passwd = unsafe {
        let passwd = Passwd::new(result);
        SelfRef::new(passwd, buf)
    };

    Ok(passwd)
}

pub fn initgroups(user: &CStr, basegroup: gid_t) -> Result<(), ()> {
    unsafe { libc::initgroups(user.as_ptr(), basegroup as _).map(|| warn!("initgroups")) }
}

pub fn getsid(pid: pid_t) -> Result<pid_t, ()> {
    let res = unsafe { libc::getsid(pid) };
    if res == libc::ESRCH {
        errx!("can not get sid");
    }
    Ok(res)
}

#[derive(Debug)]
pub struct ProcessInfo {
    pub ppid: pid_t,
    pub sid: pid_t,
    pub start_time: u64,
    pub tty: u32,
}

/// # CLOCK_MONOTONIC_RAW (on macOS)
/// clock that increments monotonically, tracking the time since an arbitrary point like
/// CLOCK_MONOTONIC.  However, this clock is unaffected by frequency or time adjustments.  It
/// should not be compared to other system time sources.
///
/// # CLOCK_BOOTTIME (since Linux 2.6.39; Linux-specific)
/// A nonsettable system-wide clock that is identical to CLOCK_MONOTONIC, except that it also includes any time that the system  is  suspended.   This allows applications to get a suspend-aware monotonic clock without having to deal with
/// the complications of CLOCK_REALTIME, which may have discontinuities if the time is changed using settimeofday(2)  or
/// similar.
///
/// # CLOCK_REALTIME
/// the system's real time (i.e. wall time) clock, expressed as the amount of time since the
/// Epoch.  This is the same as the value returned by gettimeofday(2).
pub fn clock_gettime(clock_id: clockid_t) -> Result<Time, ()> {
    unsafe {
        let mut time: Time = mem::zeroed();
        bindings::clock_gettime(clock_id, &raw mut time as _).map(|| warn!("clock_gettime"))?;
        Ok(time)
    }
}

pub fn fstat(fd: c_int) -> Result<bindings::stat, ()> {
    unsafe {
        let mut stat = mem::zeroed();
        bindings::fstat(fd, &raw mut stat).map(|| warn!("fstat"))?;
        Ok(stat)
    }
}

pub fn fchown(fd: c_int, owner: uid_t, group: gid_t) -> Result<(), io::Error> {
    unsafe { libc::fchown(fd, owner, group).map(io::Error::last_os_error) }
}

pub fn futimens(fd: c_int, times: &[Time; 2]) -> Result<(), ()> {
    unsafe { bindings::futimens(fd, times.as_ptr() as _).map(|| warn!("set futimens")) }
}

fn getpwnam(name: &CStr) -> Option<libc::passwd> {
    unsafe {
        let ptr = libc::getpwnam(name.as_ptr());
        if ptr.is_null() {
            return None;
        }
        Some(*ptr)
    }
}

fn getgrnam(name: &CStr) -> Option<libc::group> {
    unsafe {
        let ptr = libc::getgrnam(name.as_ptr());
        if ptr.is_null() {
            return None;
        }
        Some(*ptr)
    }
}

pub fn pam_start(
    service: &CStr,
    user: &CStr,
    pam_conv: &bindings::pam_conv,
    pamh: &mut *mut pam_handle_t,
) -> Result<(), ()> {
    unsafe {
        bindings::pam_start(service.as_ptr(), user.as_ptr(), pam_conv, pamh)
            .map_pam(|| warnx!("pam_start({:?}, {:?}, ?, ?): failed", service, user))
    }
}

pub fn pam_set_item<'a>(
    pamh: &'a mut pam_handle_t,
    item_type: c_int,
    item: &CStr,
) -> Result<(), &'a CStr> {
    unsafe {
        bindings::pam_set_item(pamh, item_type, item.as_ptr() as *const libc::c_void)
            .map_to_pam_str(pamh)
    }
}

pub fn pam_authenticate(pamh: &mut pam_handle_t, flags: c_int) -> Result<(), ()> {
    unsafe { bindings::pam_authenticate(pamh, flags).map_pam(|| ()) }
}

pub fn pam_acct_mgmt(pamh: &mut pam_handle_t, flags: c_int) -> Result<(), c_int> {
    unsafe { bindings::pam_acct_mgmt(pamh, flags).map_pam_direct() }
}

pub fn pam_chauthtok(pamh: &mut pam_handle_t, flags: c_int) -> Result<(), c_int> {
    unsafe { bindings::pam_chauthtok(pamh, flags).map_pam_direct() }
}

pub fn pam_close_session(pamh: &mut pam_handle_t, flags: c_int) -> Result<(), ()> {
    unsafe {
        bindings::pam_close_session(pamh, flags)
            .map_to_pam_str(pamh)
            .map_err(|e| warnx!("pam_close_session: {:?}", e))
    }
}

pub fn pam_strerror(pamh: &mut pam_handle_t, error_number: c_int) -> &CStr {
    unsafe { CStr::from_ptr(bindings::pam_strerror(pamh, error_number)) }
}

pub fn pam_setcred(pamh: &mut pam_handle_t, flags: c_int) -> Result<(), (c_int, &CStr)> {
    let ret = unsafe { bindings::pam_setcred(pamh, flags) };
    ret.map_to_pam_str(pamh).map_err(|e| (ret, e))
}

pub fn pam_end(pamh: &mut pam_handle_t, status: c_int) -> c_int {
    unsafe { bindings::pam_end(pamh, status) }
}

#[inline]
fn c_to_os(str: &CStr) -> OsString {
    OsStr::from_bytes(str.to_bytes()).to_os_string()
}

fn create_env(mypw: &Passwd, target_pw: &Passwd) -> HashMap<OsString, OsString> {
    let copyset = ["DISPLAY", "TERM"];
    let mut envs = HashMap::new();
    envs.insert("DOAS_USER".into(), c_to_os(&mypw.pw_name));
    envs.insert("HOME".into(), c_to_os(&target_pw.pw_dir));
    envs.insert("LOGNAME".into(), c_to_os(&target_pw.pw_name));
    envs.insert("SHELL".into(), c_to_os(&target_pw.pw_shell));
    envs.insert("USER".into(), c_to_os(&target_pw.pw_name));
    fill_env_inherit(&copyset, &mut envs);

    envs
}

fn set_path(envs: &mut HashMap<OsString, OsString>, has_cmd: bool) {
    const PATH: &str = "PATH";
    let val = if !has_cmd && let Some(val) = env::var_os(PATH) {
        val
    } else {
        SAFE_PATH.into()
    };
    envs.insert(PATH.into(), val);
}

pub fn prep_env(mypw: &Passwd, target_pw: &Passwd, rule: Config) -> HashMap<OsString, OsString> {
    let mut envs = create_env(mypw, target_pw);
    set_path(&mut envs, rule.has_cmd());
    if rule.options.keepenv {
        keep_envs(&mut envs);
    }
    apply_rule_envs(&mut envs, rule.options.envs);
    envs
}

fn keep_envs(envs: &mut HashMap<OsString, OsString>) {
    for (key, val) in env::vars_os() {
        // ignore duplicate envs
        envs.entry(key).or_insert(val);
    }
}

fn apply_rule_envs(envs: &mut HashMap<OsString, OsString>, setenvs: Vec<Env>) {
    for env in setenvs {
        match env {
            Env::Keep(key) => {
                if let Some(val) = env::var_os(&key) {
                    envs.insert(key.into(), val);
                }
            }
            Env::Set { key, val } => match val {
                Val::New(val) => {
                    envs.insert(key.into(), val.into());
                }
                Val::FromEnv(val_key) => {
                    if let Some(val) = env::var_os(&val_key) {
                        envs.insert(key.into(), val);
                    }
                }
            },
            Env::Remove(key) => {
                envs.remove::<OsStr>(key.as_ref());
            }
        }
    }
}

fn fill_env_inherit<S>(copy_from: &[S], envs: &mut HashMap<OsString, OsString>)
where
    S: AsRef<OsStr>,
{
    for s in copy_from {
        if let Some(val) = env::var_os(s.as_ref()) {
            envs.insert(s.as_ref().to_os_string(), val);
        }
    }
}

pub fn parse_uid(uid: &str) -> Result<uid_t, ()> {
    let cstr = CString::new(uid).map_err(|_| ())?;
    if let Some(pw) = getpwnam(cstr.as_c_str()) {
        if pw.pw_uid == sys::UID_MAX {
            return Err(());
        }
        return Ok(pw.pw_uid);
    }
    let uid = uid.parse().map_err(|_| ())?;
    if uid == sys::UID_MAX {
        return Err(());
    }
    Ok(uid)
}

pub fn parse_gid(gid: &str) -> Result<gid_t, ()> {
    let cstr = CString::new(gid).map_err(|_| ())?;
    if let Some(gr) = getgrnam(cstr.as_c_str()) {
        if gr.gr_gid == sys::GID_MAX {
            return Err(());
        }
        return Ok(gr.gr_gid);
    }
    let gid = gid.parse().map_err(|_| ())?;
    if gid == sys::GID_MAX {
        return Err(());
    }
    Ok(gid)
}

pub fn syslog(priority: c_int, msg: &CStr) {
    unsafe {
        // use %s, in case the msg contains a '%'
        libc::syslog(priority, c"%s".as_ptr(), msg);
    }
}

#[macro_export]
macro_rules! syslog {
    ($priority:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {
        let s = $crate::c_format!($fmt, $($arg,)*);
        $crate::c::syslog($priority, &s);
    };
}

pub fn perror(str: &CStr) {
    unsafe {
        libc::perror(str.as_ptr());
    }
}

pub fn eprint(str: &[u8]) {
    if let Err(e) = std::io::stderr().write_all(str) {
        panic!("failed printing to stderr: {e}");
    }
}

trait MapErrNo {
    fn map<F, T>(self, f: F) -> Result<(), T>
    where
        F: FnOnce() -> T;
    fn map_pam<F, T>(self, f: F) -> Result<(), T>
    where
        F: FnOnce() -> T;
    fn map_to_pam_str(self, pamh: &mut pam_handle_t) -> Result<(), &CStr>;
    fn map_pam_direct(self) -> Result<(), Self>
    where
        Self: Sized;
}

impl MapErrNo for c_int {
    // -1 means failure
    fn map<F, T>(self, f: F) -> Result<(), T>
    where
        F: FnOnce() -> T,
    {
        if self == -1 { Err(f()) } else { Ok(()) }
    }

    fn map_pam<F, T>(self, f: F) -> Result<(), T>
    where
        F: FnOnce() -> T,
    {
        if self == bindings::PAM_SUCCESS as i32 {
            Ok(())
        } else {
            Err(f())
        }
    }

    fn map_pam_direct(self) -> Result<(), Self> {
        if self == bindings::PAM_SUCCESS as i32 {
            Ok(())
        } else {
            Err(self)
        }
    }

    fn map_to_pam_str(self, pamh: &mut pam_handle_t) -> Result<(), &CStr> {
        if self == bindings::PAM_SUCCESS as i32 {
            Ok(())
        } else {
            Err(pam_strerror(pamh, self))
        }
    }
}
