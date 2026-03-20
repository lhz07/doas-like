use libc::{c_char, c_int, gid_t, uid_t};
use std::{
    borrow::Cow,
    collections::HashMap,
    env,
    ffi::{CStr, CString, OsStr, OsString},
    mem,
    os::unix::ffi::OsStrExt,
};

use crate::{
    bindings::{self, pam_handle_t},
    err, errprint, errx,
};

pub fn getuid() -> uid_t {
    unsafe { libc::getuid() }
}

pub fn getgid() -> gid_t {
    unsafe { libc::getgid() }
}

pub fn getgroups() -> Result<Vec<gid_t>, ()> {
    use bindings::NGROUPS_MAX;
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

pub fn geteuid() -> uid_t {
    unsafe { libc::geteuid() }
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

pub fn setprogname(name: &CStr) {
    unsafe { libc::setprogname(name.as_ptr()) }
}

/// It is guaranteed that the ptr in passwd is always valid
pub struct Passwd {
    pub passwd: libc::passwd,
    _buf: Vec<i8>,
}

impl std::ops::Deref for Passwd {
    type Target = libc::passwd;
    fn deref(&self) -> &Self::Target {
        &self.passwd
    }
}

pub fn getpwuid(uid: uid_t) -> Result<Passwd, ()> {
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
    let passwd = unsafe { *result };

    let passwd = Passwd { passwd, _buf: buf };

    Ok(passwd)
}

/// # Safety
/// `user` should be valid ptr
pub unsafe fn initgroups(user: *const c_char, basegroup: libc::c_int) -> Result<(), ()> {
    unsafe { libc::initgroups(user, basegroup).map(|| errprint!("initgroups")) }
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
    pamh: &mut *mut bindings::pam_handle_t,
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
    pamh: &'a mut bindings::pam_handle_t,
    item_type: libc::c_int,
    item: &CStr,
) -> Result<(), &'a CStr> {
    unsafe {
        bindings::pam_set_item(pamh, item_type, item.as_ptr() as *const libc::c_void)
            .map_to_pam_str(pamh)
    }
}

pub fn pam_authenticate(pamh: &mut bindings::pam_handle_t, flags: c_int) -> Result<(), ()> {
    unsafe { bindings::pam_authenticate(pamh, flags).mapx(|_| ()) }
}

pub fn pam_acct_mgmt(pamh: &mut bindings::pam_handle_t, flags: c_int) -> Result<(), c_int> {
    unsafe { bindings::pam_acct_mgmt(pamh, flags).map_direct() }
}

pub fn pam_chauthtok(pamh: &mut bindings::pam_handle_t, flags: c_int) -> Result<(), c_int> {
    unsafe { bindings::pam_chauthtok(pamh, flags).map_direct() }
}

pub fn pam_close_session(pamh: &mut bindings::pam_handle_t, flags: c_int) -> Result<(), ()> {
    unsafe {
        bindings::pam_close_session(pamh, flags)
            .mapx_pam(pamh, |str| errprint!("pam_close_session: {str}",))
    }
}

pub fn pam_strerror(pamh: &pam_handle_t, error_number: c_int) -> &CStr {
    unsafe { CStr::from_ptr(bindings::pam_strerror(pamh, error_number)) }
}

pub fn pam_setcred(
    pamh: &mut bindings::pam_handle_t,
    flags: libc::c_int,
) -> Result<(), (c_int, &CStr)> {
    let ret = unsafe { bindings::pam_setcred(pamh, flags) };
    ret.map_to_pam_str(pamh).map_err(|e| (ret, e))
}

pub fn pam_end(pamh: &mut pam_handle_t, status: c_int) -> c_int {
    unsafe { bindings::pam_end(pamh, status) }
}

unsafe fn c_to_os(ptr: *const c_char) -> OsString {
    OsStr::from_bytes(unsafe { CStr::from_ptr(ptr) }.to_bytes()).to_os_string()
}

fn create_env(mypw: &libc::passwd, target_pw: &libc::passwd) -> HashMap<OsString, OsString> {
    let copyset = ["DISPLAY", "TERM", "PATH"];
    let mut envs = HashMap::new();
    unsafe {
        envs.insert("DOAS_USER".into(), c_to_os(mypw.pw_name));
        envs.insert("HOME".into(), c_to_os(target_pw.pw_dir));
        envs.insert("LOGNAME".into(), c_to_os(target_pw.pw_name));
        envs.insert("SHELL".into(), c_to_os(target_pw.pw_shell));
        envs.insert("USER".into(), c_to_os(target_pw.pw_name));
    }

    fill_env_inherit(&copyset, &mut envs);

    envs
}

pub fn prep_env(mypw: &libc::passwd, target_pw: &libc::passwd) -> HashMap<OsString, OsString> {
    create_env(mypw, target_pw)
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

fn perror(str: &CStr) {
    unsafe {
        libc::perror(str.as_ptr());
    }
}

trait MapErrNo {
    fn map<F>(self, f: F) -> Result<(), ()>
    where
        F: FnOnce();
    fn mapx<F>(self, f: F) -> Result<(), ()>
    where
        F: FnOnce(libc::c_int);
    fn mapx_pam<'a, F>(self, pamh: &bindings::pam_handle_t, f: F) -> Result<(), ()>
    where
        F: FnOnce(Cow<'a, str>);
    fn map_to_pam_str(self, pamh: &pam_handle_t) -> Result<(), &CStr>;
    fn map_direct(self) -> Result<(), Self>
    where
        Self: Sized;
}

impl MapErrNo for libc::c_int {
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
    fn mapx<F>(self, f: F) -> Result<(), ()>
    where
        F: FnOnce(libc::c_int),
    {
        if self == 0 {
            Ok(())
        } else {
            f(self);
            Err(())
        }
    }
    fn map_direct(self) -> Result<(), Self> {
        if self == 0 { Ok(()) } else { Err(self) }
    }
    fn mapx_pam<'a, F>(self, pamh: &bindings::pam_handle_t, f: F) -> Result<(), ()>
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
