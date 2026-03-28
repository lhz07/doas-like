use crate::{PROVE_PATH, c, errx, insults, pam, warn};
use libc::uid_t;
use objc2::runtime::Bool;
use objc2_foundation::ns_string;
use objc2_local_authentication::{LAContext, LAPolicy};
use std::{
    borrow::Cow,
    ffi::CStr,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    rc::Rc,
    sync::atomic::AtomicBool,
    thread,
};

fn prove(path: &str) -> Result<String, Cow<'static, str>> {
    let mut file = fs::File::open(path).map_err(|e| format!("{e}"))?;
    // check file permission
    let meta = file.metadata().map_err(|e| format!("{e}"))?;
    // don't forget to mask out file type bits
    // file type | special | permission
    //    010    |    0    |    400
    if (meta.permissions().mode() & 0o777) != 0o0400 {
        return Err("prove file permisson mode is not 0400".into());
    }
    if meta.uid() != 0 {
        return Err("prove file is not owned by root".into());
    }

    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("{e}"))?;
    Ok(content)
}

pub fn auth(target_user: &CStr, myname: &CStr, insult: bool, real_uid: uid_t) -> Result<(), ()> {
    // downgrade to real uid
    c::seteuid(real_uid)?;
    if auth_by_local_authentication() {
        // upgrade to euid
        c::setreuid(0, 0)?;
        return Ok(());
    }
    // upgrade to euid
    c::setreuid(0, 0)?;

    // fall back to pam authentication
    // prove we are setuid program first
    match prove(PROVE_PATH) {
        Ok(s) => println!("doas prove: {}", s.trim()),
        Err(e) => {
            warn!("read {PROVE_PATH} error: {e}, \nit is strongly recommended to use a prove file")
        }
    }
    for _ in 0..3 {
        let res = pam::pam_auth(target_user, myname);
        if res.is_ok() {
            return res;
        }
        if insult {
            eprintln!("{}", insults::get_an_insult());
        } else {
            eprintln!("Sorry, please try again");
        }
    }
    errx!("Authentication failed");
}

fn auth_by_local_authentication() -> bool {
    let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrCompanion;
    let context = unsafe { LAContext::new() };
    if unsafe { context.canEvaluatePolicy_error(policy).is_ok() } {
        let successful = Rc::new(AtomicBool::new(false));
        let finished = Rc::new(AtomicBool::new(false));
        let mark = thread::current();
        let finished_clone = finished.clone();
        let successful_clone = successful.clone();
        let block = block2::StackBlock::new(move |success: Bool, _| {
            successful_clone.store(success.as_bool(), std::sync::atomic::Ordering::Relaxed);
            finished_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            mark.unpark();
        });
        let reason = ns_string!("authenticate to get root privilege");
        unsafe { context.evaluatePolicy_localizedReason_reply(policy, reason, &block) };
        while !finished.load(std::sync::atomic::Ordering::Relaxed) {
            thread::park();
        }
        successful.load(std::sync::atomic::Ordering::Relaxed)
    } else {
        false
    }
}
