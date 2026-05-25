use doas::{
    CNAME, CONF_PATH, PATH_KEY, SAFE_PATH,
    c::{self},
    command::CmdArgs,
    config::{Config, check_config, permit},
    errx,
    sys::{self},
    syslog,
    timestamp::{self},
    verify, vidoas, warnx,
};
use libc::{LOG_AUTHPRIV, LOG_INFO, LOG_NOTICE, gid_t};
use std::{
    env,
    ffi::{OsStr, OsString},
    os::unix::{ffi::OsStrExt as _, process::CommandExt as _},
    process,
};

fn inner_main() -> Result<(), ()> {
    let real_uid = c::getuid();
    let origin_euid = c::geteuid();

    c::setprogname(CNAME);
    // close or set CLOEXEC for derived fds
    if let Err(e) = sys::closefrom(libc::STDERR_FILENO + 1) {
        errx!("close fd error: {e}");
    }

    // parse args
    let args = CmdArgs::parse()?;

    if args.clear {
        return timestamp::clear();
    }

    let target_uid = match args.user {
        Some(uid) => c::parse_uid(&uid).inspect_err(|_| warnx!("unknown user"))?,
        None => 0,
    };
    let mypw = c::getpwuid(real_uid)?;
    let groups = c::getgroups()?;

    let argvs = if args.shell {
        match env::var_os("SHELL") {
            Some(sh) => vec![sh],
            None => {
                let sh = OsStr::from_bytes(mypw.pw_shell.to_bytes()).to_os_string();
                vec![sh]
            }
        }
    } else if args.vidoas {
        let cmd = env::var_os("EDITOR").unwrap_or_else(|| OsString::from("vim"));
        vec![cmd, OsString::from(CONF_PATH)]
    } else {
        args.command
    };

    if let Some(path) = args.config {
        // downgrade to real uid.
        c::setreuid(real_uid, real_uid)?;
        return check_config(
            path.as_ref(),
            real_uid,
            &groups,
            target_uid,
            &argvs,
            args.verbose,
            false,
        )
        .map_err(|_| ());
    }

    let cmdline = argvs.join(" ".as_ref());
    let cmd = &argvs[0];
    let cmd_args = &argvs[1..];
    let target_pw = c::getpwuid(target_uid)?;

    if origin_euid != 0 {
        errx!("not installed setuid");
    }

    let config = match Config::parse(CONF_PATH.as_ref(), true) {
        Ok(c) => c,
        Err(e) => errx!("config error: {e}"),
    };

    let Some(rule) = permit(config, real_uid, &groups, target_uid, cmd, cmd_args) else {
        syslog!(
            LOG_AUTHPRIV | LOG_NOTICE,
            "command not permitted for {}: {}",
            mypw.pw_name,
            cmdline
        );
        let err = std::io::Error::from_raw_os_error(libc::EPERM);
        errx!("{err}");
    };

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
        // authenticate user
        verify::auth(
            &target_pw.pw_name,
            &mypw.pw_name,
            rule.options.insult,
            rule.options.pwfeedback,
            real_uid,
        )?;
    }
    if let Some(file) = persist_file
        && let Some(dur) = rule.options.persist
    {
        let _ = timestamp::set(&file, dur);
    }

    c::setregid(target_pw.pw_gid, target_pw.pw_gid)?;
    c::initgroups(&target_pw.pw_name, target_pw.pw_gid as gid_t)?;
    c::setreuid(target_uid, target_uid)?;
    if !rule.options.nolog {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("(failed)"));
        syslog!(
            LOG_AUTHPRIV | LOG_INFO,
            "{} ran command {} as {} from {}",
            mypw.pw_name,
            cmdline,
            target_pw.pw_name,
            cwd,
        );
    }
    let cmd = if rule.has_cmd() {
        // search program in safe PATH
        c::search_path(cmd, SAFE_PATH.as_ref())
    } else {
        // search program in PATH
        c::search_path(cmd, env::var_os(PATH_KEY).unwrap_or_default().as_ref())
    }
    .ok_or_else(|| warnx!("{:?}: command not found", cmd))?;

    let envs = c::prep_env(&mypw, &target_pw, rule);
    if args.vidoas {
        vidoas::run(
            real_uid,
            &groups,
            target_uid,
            &cmd,
            &argvs,
            envs,
            &mypw.pw_name,
        )
    } else {
        let err = process::Command::new(&cmd)
            .args(cmd_args)
            .env_clear()
            .envs(envs)
            .exec();
        if err.kind() == std::io::ErrorKind::NotFound {
            errx!("{:?}: command not found", cmd);
        }
        errx!("exec failed: {err}");
    }
}

fn main() -> process::ExitCode {
    match inner_main() {
        Ok(_) => process::ExitCode::SUCCESS,
        Err(_) => process::ExitCode::FAILURE,
    }
}
