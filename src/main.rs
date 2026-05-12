use clap::Parser;
use doas::{
    CNAME, CONF_PATH,
    c::{self},
    command::CliArgs,
    config::{Config, check_config, permit},
    errprint, errx, syslog, timestamp, verify,
};
use libc::{LOG_AUTHPRIV, LOG_INFO, LOG_NOTICE};
use std::{
    env,
    ffi::{CStr, OsStr},
    os::unix::{ffi::OsStrExt, process::CommandExt},
    process,
};

fn inner_main() -> Result<(), ()> {
    let real_uid = c::getuid();
    let origin_euid = c::geteuid();

    c::setprogname(CNAME);
    // no need to close fds, because std::process::Command will do it

    // parse args
    let args = CliArgs::parse();

    if args.clear {
        return timestamp::clear();
    }

    let target_uid = match args.user {
        Some(uid) => c::parse_uid(&uid).inspect_err(|_| errprint!("unknown user"))?,
        None => 0,
    };
    let mypw = c::getpwuid(real_uid)?;
    let groups = c::getgroups()?;

    let argvs = if args.shell {
        match env::var_os("SHELL") {
            Some(sh) => vec![sh],
            None => {
                let sh = unsafe { CStr::from_ptr(mypw.pw_shell) };
                let sh = OsStr::from_bytes(sh.to_bytes()).to_os_string();
                vec![sh]
            }
        }
    } else {
        args.command
    };

    if let Some(path) = args.config {
        return check_config(&path, real_uid, &groups, target_uid, &argvs);
    }

    let cmdline = {
        let mut argvs = argvs.iter();
        let mut buf = Vec::new();
        if let Some(first) = argvs.next() {
            buf.extend(first.as_bytes());
            for str in argvs {
                buf.push(' ' as u8);
                buf.extend(str.as_bytes());
            }
        }
        buf.push(0);
        buf
    };
    let cmd = &argvs[0];
    let cmd_args = &argvs[1..];
    let target_pw = c::getpwuid(target_uid)?;

    if origin_euid != 0 {
        errx!("not installed setuid");
    }

    let config = match Config::parse(CONF_PATH, true) {
        Ok(c) => c,
        Err(e) => errx!("config error: {e}"),
    };
    let myname = unsafe { CStr::from_ptr(mypw.pw_name) };

    let Some(rule) = permit(config, real_uid, &groups, target_uid, cmd, cmd_args) else {
        syslog!(
            LOG_AUTHPRIV | LOG_NOTICE,
            "command not permitted for {}: {}",
            myname,
            cmdline
        );
        let err = std::io::Error::from_raw_os_error(libc::EPERM);
        errx!("{err}");
    };

    let target_user = unsafe { CStr::from_ptr(target_pw.pw_name) };
    let mut persist_file = None;
    let persist_pass = {
        if let Some(dur) = rule.options.persist
            && let Ok(file) = timestamp::open(dur)
        {
            let file = persist_file.insert(file);
            timestamp::check(file, dur).is_ok_and(|b| b)
        } else {
            false
        }
    };
    if !rule.options.nopass && !persist_pass {
        if args.non_interactive {
            errx!("Authentication required");
        }
        // downgrade to real uid
        c::seteuid(real_uid)?;
        // authenticate user
        verify::auth(target_user, myname, rule.options.insult)?;
        // upgrade to euid
        c::setreuid(0, 0)?;
    }
    if let Some(file) = persist_file
        && let Some(dur) = rule.options.persist
    {
        let _ = timestamp::set(&file, dur);
    }

    c::setregid(target_pw.pw_gid, target_pw.pw_gid)?;
    unsafe { c::initgroups(target_pw.pw_name, target_pw.pw_gid as i32)? };
    c::setreuid(target_uid, target_uid)?;
    if !rule.options.nolog {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("(failed)"));
        syslog!(
            LOG_AUTHPRIV | LOG_INFO,
            "{} ran command {} as {} from {}",
            myname,
            cmdline,
            target_user,
            cwd,
        );
    }
    let envs = c::prep_env(&mypw, &target_pw, rule.options.keepenv, rule.options.envs);
    let err = process::Command::new(cmd)
        .args(cmd_args)
        .env_clear()
        .envs(envs)
        .exec();
    errx!("exec failed: {err}");
}

fn main() -> process::ExitCode {
    match inner_main() {
        Ok(_) => process::ExitCode::SUCCESS,
        Err(_) => process::ExitCode::FAILURE,
    }
}
