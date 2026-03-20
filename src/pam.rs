use std::{
    ffi::{CStr, CString},
    mem::ManuallyDrop,
    process, ptr,
};

use libc::{c_char, c_int, c_void};
use zeroize::Zeroizing;

use crate::{
    bindings::{self, pam_handle, pam_message, pam_response},
    c, warn,
};

unsafe fn pam_prompt(msg: *const c_char, echo_on: bool) -> Result<CString, u32> {
    use bindings::{PAM_CONV_ERR, PAM_MAX_RESP_SIZE, RPP_ECHO_OFF, RPP_ECHO_ON, RPP_REQUIRE_TTY};
    let flags = RPP_REQUIRE_TTY | if echo_on { RPP_ECHO_ON } else { RPP_ECHO_OFF };
    let mut buf = [0; PAM_MAX_RESP_SIZE as usize];
    let pass = unsafe {
        let pass = bindings::readpassphrase(msg, buf.as_mut_ptr(), size_of_val(&buf), flags as i32);
        if pass.is_null() {
            return Err(PAM_CONV_ERR);
        }
        CStr::from_ptr(pass).to_owned()
    };
    Zeroizing::new(buf);
    Ok(pass)
}

unsafe extern "C" fn pamconv(
    nmsgs: c_int,
    msgs: *mut *const pam_message,
    rsps: *mut *mut pam_response,
    _: *mut c_void,
) -> c_int {
    let mut response = ZeroDrop::new(Vec::with_capacity(nmsgs as usize));
    let msgs = unsafe { std::slice::from_raw_parts(msgs, nmsgs as usize) };
    for msg in msgs {
        let msg = unsafe { &**msg };
        match msg.msg_style as u32 {
            bindings::PAM_PROMPT_ECHO_OFF | bindings::PAM_PROMPT_ECHO_ON => {
                let pass = match unsafe {
                    pam_prompt(
                        msg.msg,
                        msg.msg_style == bindings::PAM_PROMPT_ECHO_ON as i32,
                    )
                } {
                    Ok(pass) => pass,
                    Err(e) => return e as i32,
                };
                let rsp = pam_response {
                    resp: pass.into_raw(),
                    resp_retcode: 0,
                };
                response.push(rsp);
            }
            bindings::PAM_ERROR_MSG | bindings::PAM_TEXT_INFO => {
                let msg = unsafe { CStr::from_ptr(msg.msg).to_string_lossy() };
                eprintln!("{}", msg);
            }
            _ => {
                eprintln!("invalid PAM msg_style {}", msg.msg_style);
                process::exit(1);
            }
        }
    }
    let resp = response.into_inner().leak();
    unsafe {
        *rsps = resp.as_mut_ptr();
    }
    bindings::PAM_SUCCESS as i32
}

struct ZeroDrop {
    vec: ManuallyDrop<Vec<pam_response>>,
}

impl ZeroDrop {
    fn new(vec: Vec<pam_response>) -> Self {
        Self {
            vec: ManuallyDrop::new(vec),
        }
    }
    fn into_inner(self) -> Vec<pam_response> {
        let mut new_guard = ManuallyDrop::new(self);
        unsafe { ManuallyDrop::take(&mut new_guard.vec) }
    }
}

impl std::ops::Deref for ZeroDrop {
    type Target = Vec<pam_response>;
    fn deref(&self) -> &Self::Target {
        &self.vec
    }
}

impl std::ops::DerefMut for ZeroDrop {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vec
    }
}

impl Drop for ZeroDrop {
    fn drop(&mut self) {
        let vec = unsafe { ManuallyDrop::take(&mut self.vec) };
        for res in vec {
            let cstr = unsafe { CString::from_raw(res.resp) };
            Zeroizing::new(cstr);
        }
    }
}

pub fn pam_auth(target_user: &CStr, myname: &CStr) -> Result<(), ()> {
    let mut pam_guard = unsafe {
        let conv = bindings::pam_conv {
            conv: Some(pamconv),
            appdata_ptr: ptr::null_mut(),
        };
        let mut pamh = ptr::null_mut();
        c::pam_start(c"sudo", myname, &conv, &mut pamh)?;
        PamGuard {
            pamh: &mut *pamh,
            sess: 0,
            cred: 0,
        }
    };
    if let Err(e) = c::pam_set_item(pam_guard.pamh, bindings::PAM_RUSER as i32, myname) {
        warn!(
            "pam_set_item(?, PAM_RUSER, \"{}\"): {}",
            myname.to_string_lossy(),
            e.to_string_lossy(),
        );
    }
    c::pam_authenticate(pam_guard.pamh, 0)?;

    // account not vaild or changing the auth token failed
    if let Err(ret) = c::pam_acct_mgmt(pam_guard.pamh, 0)
        && ((ret != bindings::PAM_NEW_AUTHTOK_REQD as i32)
            || c::pam_chauthtok(pam_guard.pamh, bindings::PAM_CHANGE_EXPIRED_AUTHTOK).is_err())
    {
        return Err(());
    }
    // set PAM_USER to the user we want to be
    if let Err(e) = c::pam_set_item(pam_guard.pamh, bindings::PAM_USER as i32, target_user) {
        warn!(
            "pam_set_item(?, PAM_USER, \"{}\"): {}",
            target_user.to_string_lossy(),
            e.to_string_lossy()
        );
    }

    if let Err((_, e)) = c::pam_setcred(pam_guard.pamh, bindings::PAM_REINITIALIZE_CRED) {
        warn!(
            "pam_setcred(?, PAM_REINITIALIZE_CRED): {}",
            e.to_string_lossy()
        );
    } else {
        pam_guard.cred = 1;
    }
    Ok(())
}

struct PamGuard<'a> {
    pamh: &'a mut pam_handle,
    sess: c_int,
    cred: c_int,
}

impl Drop for PamGuard<'_> {
    fn drop(&mut self) {
        let mut status = 0;
        if self.sess != 0 && c::pam_close_session(self.pamh, 0).is_err() {
            process::exit(1);
        }
        if self.cred != 0
            && let Err((ret, e)) =
                c::pam_setcred(self.pamh, bindings::PAM_DELETE_CRED | bindings::PAM_SILENT)
        {
            warn!(
                "pam_setcred(?, PAM_DELETE_CRED | PAM_SILENT): {}",
                e.to_string_lossy()
            );
            status = ret;
        }
        c::pam_end(self.pamh, status);
    }
}
