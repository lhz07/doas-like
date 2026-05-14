use crate::{
    SAFE_PATH,
    bindings::{self, pam_handle_t, proc_bsdinfo},
    config::{Config, Env, Val},
    err, errprint, errx,
    timestamp::Time,
    utils::selfref::{OwnedRef, SelfRef},
    warn,
};
use libc::{c_char, c_int, clockid_t, gid_t, pid_t, uid_t};
use std::{
    borrow::Cow,
    collections::HashMap,
    env,
    ffi::{CStr, CString, OsStr, OsString},
    io, mem,
    os::unix::ffi::OsStrExt,
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
    unsafe { libc::setprogname(name.as_ptr()) }
}

pub fn setuid(uid: uid_t) -> Result<(), ()> {
    unsafe { libc::setuid(uid).map(|| errprint!("setuid")) }
}

pub fn seteuid(uid: uid_t) -> Result<(), ()> {
    unsafe { libc::seteuid(uid).map(|| errprint!("seteuid")) }
}

pub fn setreuid(ruid: uid_t, euid: uid_t) -> Result<(), ()> {
    unsafe { libc::setreuid(ruid, euid).map(|| errprint!("setreuid")) }
}

pub fn setregid(rgid: uid_t, egid: uid_t) -> Result<(), ()> {
    unsafe { libc::setregid(rgid, egid).map(|| errprint!("setregid")) }
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

#[cfg(not(target_os = "macos"))]
pub fn get_all_groups() -> Result<Vec<gid_t>, ()> {
    let mut groups = getgroups()?;
    groups.push(getgid());
    Ok(groups)
}

pub struct Passwd {
    pub pw_name: OwnedRef<CStr>,
    pub pw_passwd: OwnedRef<CStr>,
    pub pw_uid: uid_t,
    pub pw_gid: gid_t,
    pub pw_class: OwnedRef<CStr>,
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
                pw_class: OwnedRef::new(CStr::from_ptr((*passwd).pw_class)),
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
                .ok_or_else(|| errprint!("getpwuid: buf size overflow"))?;
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

pub fn initgroups(user: &CStr, basegroup: c_int) -> Result<(), ()> {
    unsafe { libc::initgroups(user.as_ptr(), basegroup).map(|| errprint!("initgroups")) }
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

pub fn get_proc_info() -> Result<ProcessInfo, ()> {
    let ppid = getppid();
    let sid = getsid(0)?;
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

/// # CLOCK_MONOTONIC_RAW
/// clock that increments monotonically, tracking the time since an arbitrary point like
/// CLOCK_MONOTONIC.  However, this clock is unaffected by frequency or time adjustments.  It
/// should not be compared to other system time sources.
///
/// # CLOCK_REALTIME
/// the system's real time (i.e. wall time) clock, expressed as the amount of time since the
/// Epoch.  This is the same as the value returned by gettimeofday(2).
pub fn clock_gettime(clock_id: clockid_t) -> Result<Time, ()> {
    unsafe {
        let mut time: Time = mem::zeroed();
        bindings::clock_gettime(clock_id, &raw mut time as _)
            .map_minus(|| warn!("clock_gettime"))?;
        Ok(time)
    }
}

pub fn fstat(fd: c_int) -> Result<bindings::stat, ()> {
    unsafe {
        let mut stat = mem::zeroed();
        bindings::fstat(fd, &raw mut stat).map_minus(|| errprint!("fstat"))?;
        Ok(stat)
    }
}

pub fn fchown(fd: c_int, owner: uid_t, group: gid_t) -> Result<(), io::Error> {
    unsafe { libc::fchown(fd, owner, group).mapx(|_| io::Error::last_os_error()) }
}

pub fn futimens(fd: c_int, times: &[Time; 2]) -> Result<(), ()> {
    unsafe { bindings::futimens(fd, times.as_ptr() as _).map(|| errprint!("set futimens")) }
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
        bindings::pam_start(service.as_ptr(), user.as_ptr(), pam_conv, pamh).map(|| {
            errprint!(
                "pam_start(\"{}\", \"{}\", ?, ?): failed",
                service.to_string_lossy(),
                user.to_string_lossy()
            )
        })
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
    unsafe { bindings::pam_authenticate(pamh, flags).mapx(|_| ()) }
}

pub fn pam_acct_mgmt(pamh: &mut pam_handle_t, flags: c_int) -> Result<(), c_int> {
    unsafe { bindings::pam_acct_mgmt(pamh, flags).map_direct() }
}

pub fn pam_chauthtok(pamh: &mut pam_handle_t, flags: c_int) -> Result<(), c_int> {
    unsafe { bindings::pam_chauthtok(pamh, flags).map_direct() }
}

pub fn pam_close_session(pamh: &mut pam_handle_t, flags: c_int) -> Result<(), ()> {
    unsafe {
        bindings::pam_close_session(pamh, flags)
            .mapx_pam(pamh, |str| errprint!("pam_close_session: {str}",))
    }
}

pub fn pam_strerror(pamh: &pam_handle_t, error_number: c_int) -> &CStr {
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
        if pw.pw_uid == bindings::UID_MAX {
            return Err(());
        }
        return Ok(pw.pw_uid);
    }
    let uid = uid.parse().map_err(|_| ())?;
    if uid == bindings::UID_MAX {
        return Err(());
    }
    Ok(uid)
}

pub fn parse_gid(gid: &str) -> Result<gid_t, ()> {
    let cstr = CString::new(gid).map_err(|_| ())?;
    if let Some(gr) = getgrnam(cstr.as_c_str()) {
        if gr.gr_gid == bindings::GID_MAX {
            return Err(());
        }
        return Ok(gr.gr_gid);
    }
    let gid = gid.parse().map_err(|_| ())?;
    if gid == bindings::GID_MAX {
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
        let s = $crate::format_c!($fmt, $($arg,)*);
        $crate::c::syslog($priority, &s);
    };
}

pub fn perror(str: &CStr) {
    unsafe {
        libc::perror(str.as_ptr());
    }
}

trait MapErrNo {
    fn map<F>(self, f: F) -> Result<(), ()>
    where
        F: FnOnce();
    fn map_minus<F>(self, f: F) -> Result<(), ()>
    where
        F: FnOnce();
    fn mapx<F, T>(self, f: F) -> Result<(), T>
    where
        F: FnOnce(c_int) -> T;
    fn mapx_pam<'a, F>(self, pamh: &pam_handle_t, f: F) -> Result<(), ()>
    where
        F: FnOnce(Cow<'a, str>);
    fn map_to_pam_str(self, pamh: &pam_handle_t) -> Result<(), &CStr>;
    fn map_direct(self) -> Result<(), Self>
    where
        Self: Sized;
}

impl MapErrNo for c_int {
    // 0 means success
    fn map<F>(self, f: F) -> Result<(), ()>
    where
        F: FnOnce(),
    {
        if self == 0 {
            Ok(())
        } else {
            f();
            perror(c"");
            Err(())
        }
    }
    // -1 means failure
    fn map_minus<F>(self, f: F) -> Result<(), ()>
    where
        F: FnOnce(),
    {
        if self == -1 {
            f();
            perror(c"");
            Err(())
        } else {
            Ok(())
        }
    }
    fn mapx<F, T>(self, f: F) -> Result<(), T>
    where
        F: FnOnce(c_int) -> T,
    {
        if self == 0 { Ok(()) } else { Err(f(self)) }
    }
    fn map_direct(self) -> Result<(), Self> {
        if self == 0 { Ok(()) } else { Err(self) }
    }
    fn mapx_pam<'a, F>(self, pamh: &pam_handle_t, f: F) -> Result<(), ()>
    where
        F: FnOnce(Cow<'a, str>),
    {
        if self == 0 {
            Ok(())
        } else {
            let err_str = unsafe { CStr::from_ptr(bindings::pam_strerror(pamh, self)) };
            f(err_str.to_string_lossy());
            Err(())
        }
    }
    fn map_to_pam_str(self, pamh: &pam_handle_t) -> Result<(), &CStr> {
        if self == 0 {
            Ok(())
        } else {
            Err(pam_strerror(pamh, self))
        }
    }
}
