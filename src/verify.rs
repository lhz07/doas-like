use crate::{errx, insults, pam};
use libc::uid_t;
use std::ffi::CStr;

pub fn auth(
    target_user: &CStr,
    myname: &CStr,
    insult: bool,
    pwfeedback: bool,
    real_uid: uid_t,
) -> Result<(), ()> {
    #[cfg(feature = "apple-auth")]
    {
        use crate::c;
        // downgrade to real uid
        c::seteuid(real_uid)?;
        let success = auth_by_local_authentication();
        // upgrade to euid
        c::setreuid(0, 0)?;
        if success {
            return Ok(());
        }
    }

    let _ = real_uid;
    // fall back to pam authentication
    for _ in 0..3 {
        let res = pam::pam_auth(target_user, myname, pwfeedback);
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

#[cfg(feature = "apple-auth")]
fn auth_by_local_authentication() -> bool {
    use objc2::runtime::Bool;
    use objc2_foundation::ns_string;
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::{
        sync::{Arc, atomic::AtomicBool},
        thread,
    };

    let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrCompanion;
    let context = unsafe { LAContext::new() };
    if unsafe { context.canEvaluatePolicy_error(policy).is_ok() } {
        let successful = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
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
