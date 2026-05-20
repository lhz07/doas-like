use crate::{
    bindings::{self, pam_handle, pam_message, pam_response},
    c, c_format, eprintf,
    pass::read_passwd,
    syslog,
    utils::array::{Array, ArrayRef},
    warnx,
};
use libc::{LOG_AUTHPRIV, LOG_NOTICE, c_char, c_int, c_void};
use std::{
    borrow::Cow,
    ffi::{CStr, CString},
    process,
    ptr::{self, NonNull},
};
use zeroize::Zeroize as _;

fn pam_prompt(msg: &CStr, pwfeedback: bool) -> Result<NonNull<c_char>, u32> {
    use bindings::{PAM_CONV_ERR, PAM_MAX_RESP_SIZE};
    const N: usize = PAM_MAX_RESP_SIZE as usize + 1;
    let mut buf = Array::<N, _>::new();
    let safebuf = SafeBuf::new(buf.as_array_ref_mut());
    let pass = unsafe {
        read_passwd(msg, safebuf.buf, pwfeedback).map_err(|_| PAM_CONV_ERR)?;
        c::strdup(safebuf.buf.as_slice().as_ptr())
    };
    Ok(pass)
}

struct SafeBuf<'a> {
    buf: &'a mut ArrayRef<c_char>,
}

impl<'a> SafeBuf<'a> {
    fn new(buf: &'a mut ArrayRef<c_char>) -> Self {
        Self { buf }
    }
}

impl<'a> Drop for SafeBuf<'a> {
    fn drop(&mut self) {
        self.buf.as_mut_slice().zeroize();
        self.buf.spare_capacity_mut().zeroize();
    }
}

struct PamData {
    pwfeedback: bool,
    doas_prompt: CString,
}

unsafe extern "C" fn pamconv(
    nmsgs: c_int,
    msgs: *mut *const pam_message,
    rsps: *mut *mut pam_response,
    data: *mut c_void,
) -> c_int {
    let mut response = PamResp::new(nmsgs as usize);
    let mut doas_prompt = None;
    let mut pwfeedback = false;
    unsafe {
        if !data.is_null() {
            let data = data as *mut PamData;
            pwfeedback = (*data).pwfeedback;
            doas_prompt = Some((*data).doas_prompt.as_c_str());
        }
    };
    let msgs = unsafe { std::slice::from_raw_parts(msgs, nmsgs as usize) };
    for (i, msg) in msgs.iter().enumerate() {
        let msg = unsafe { &**msg };
        match msg.msg_style as u32 {
            bindings::PAM_PROMPT_ECHO_OFF | bindings::PAM_PROMPT_ECHO_ON => {
                let mut prompt = unsafe { CStr::from_ptr(msg.msg) };
                if (prompt == c"Password:" || prompt == c"Password: ")
                    && let Some(doas_prompt) = doas_prompt
                {
                    prompt = doas_prompt;
                }
                let pass = match pam_prompt(prompt, pwfeedback) {
                    Ok(pass) => pass,
                    Err(e) => return e as i32,
                };
                let rsp = pam_response {
                    resp: pass.as_ptr(),
                    resp_retcode: 0,
                };
                response[i] = rsp;
            }
            bindings::PAM_ERROR_MSG | bindings::PAM_TEXT_INFO => {
                let msg = unsafe { CStr::from_ptr(msg.msg) };
                eprintf!("{}\n", msg);
            }
            _ => {
                eprintln!("invalid PAM msg_style {}", msg.msg_style);
                process::exit(1);
            }
        }
    }
    let resp = response.into_inner();
    unsafe {
        *rsps = resp;
    }
    bindings::PAM_SUCCESS as i32
}

struct PamResp {
    slice: *mut [pam_response],
}

impl PamResp {
    fn new(nmsgs: usize) -> Self {
        let data = c::calloc(nmsgs, size_of::<pam_response>());
        let slice =
            unsafe { core::slice::from_raw_parts_mut(data.as_ptr() as *mut pam_response, nmsgs) };
        Self { slice }
    }
    fn into_inner(self) -> *mut pam_response {
        let slice = self.slice;
        std::mem::forget(self);
        slice as *mut _
    }
}

impl std::ops::Deref for PamResp {
    type Target = [pam_response];
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.slice }
    }
}

impl std::ops::DerefMut for PamResp {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.slice }
    }
}

impl Drop for PamResp {
    fn drop(&mut self) {
        let slice = &mut **self;
        for res in slice {
            if res.resp.is_null() {
                continue;
            }
            let cstr = unsafe { core::slice::from_raw_parts_mut(res.resp, libc::strlen(res.resp)) };
            cstr.zeroize();
            unsafe {
                libc::free(res.resp as *mut _);
            }
        }
        unsafe {
            libc::free(self.slice as *mut _);
        }
    }
}

pub fn pam_auth(target_user: &CStr, myname: &CStr, pwfeedback: bool) -> Result<(), ()> {
    let hostname = c::gethostname().map_or(c"?".into(), Cow::Owned);
    let name_bytes = myname.to_bytes();
    let hostname_bytes = hostname.to_bytes();
    let name_max = name_bytes.len().min(32);
    let hostname_max = hostname_bytes.len().min(32);
    let doas_prompt = c_format!(
        "doas ({}@{}) password: ",
        name_bytes[..name_max],
        hostname_bytes[..hostname_max]
    );
    let mut appdata = PamData {
        pwfeedback,
        doas_prompt,
    };
    let mut pam_guard = unsafe {
        let conv = bindings::pam_conv {
            conv: Some(pamconv),
            appdata_ptr: &raw mut appdata as *mut _,
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
        warnx!("pam_set_item(?, PAM_RUSER, {:?}): {:?}", myname, e);
    }
    if c::pam_authenticate(pam_guard.pamh, 0).is_err() {
        syslog!(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for {}", myname);
        return Err(());
    }

    // account not vaild or changing the auth token failed
    if let Err(ret) = c::pam_acct_mgmt(pam_guard.pamh, 0)
        && ((ret != bindings::PAM_NEW_AUTHTOK_REQD as i32)
            || c::pam_chauthtok(
                pam_guard.pamh,
                bindings::PAM_CHANGE_EXPIRED_AUTHTOK as c_int,
            )
            .is_err())
    {
        syslog!(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for {}", myname);
        return Err(());
    }
    // set PAM_USER to the user we want to be
    if let Err(e) = c::pam_set_item(pam_guard.pamh, bindings::PAM_USER as i32, target_user) {
        warnx!("pam_set_item(?, PAM_USER, {:?}): {:?}", target_user, e);
    }

    if let Err((_, e)) = c::pam_setcred(pam_guard.pamh, bindings::PAM_REINITIALIZE_CRED as c_int) {
        warnx!("pam_setcred(?, PAM_REINITIALIZE_CRED): {:?}", e);
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
            && let Err((ret, e)) = c::pam_setcred(
                self.pamh,
                bindings::PAM_DELETE_CRED as c_int | bindings::PAM_SILENT as c_int,
            )
        {
            warnx!("pam_setcred(?, PAM_DELETE_CRED | PAM_SILENT): {:?}", e);
            status = ret;
        }
        c::pam_end(self.pamh, status);
    }
}
