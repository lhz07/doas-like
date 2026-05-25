use crate::{
    CONF_PATH, TEMP_CONF_PATH, c,
    config::{CheckErr, ConfigError, ParsingConfig, check_config},
    eprintf, errx,
    sys::CrossStat as _,
    timestamp::Time,
    warnx,
};
use libc::{gid_t, uid_t};
use std::{
    collections::HashMap,
    ffi::{CStr, OsStr, OsString},
    fs::{self, File, OpenOptions, Permissions},
    io,
    os::{
        fd::AsRawFd as _,
        unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::Path,
    process,
    sync::LazyLock,
};

static READ_OPTIONS: LazyLock<OpenOptions> = LazyLock::new(|| {
    let mut open_read_options = fs::OpenOptions::new();
    open_read_options.read(true).custom_flags(libc::O_NOFOLLOW);
    open_read_options
});

pub fn run(
    real_uid: uid_t,
    groups: &[gid_t],
    target_uid: uid_t,
    cmd: &OsStr,
    argvs: &[OsString],
    mut envs: HashMap<OsString, OsString>,
    myname: &CStr,
) -> Result<(), ()> {
    {
        // Acquire an exclusive advisory lock on the main configuration file
        // to prevent concurrent modifications from multiple `vidoas` instances.
        let mut conf_file = READ_OPTIONS
            .open(CONF_PATH)
            .and_then(|f| {
                f.try_lock()?;
                Ok(f)
            })
            .map_err(|e| {
                warnx!("can not lock config file: {e}, perhaps another vidoas is running?");
            })?;
        let mut create_options = fs::OpenOptions::new();
        // O_NOFOLLOW not works here.
        create_options.create_new(true).write(true).mode(0o0600);
        let temp_file = match create_options.open(TEMP_CONF_PATH) {
            Ok(temp_file) => Some(temp_file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let mut input = String::new();
                loop {
                    eprint!(
                        "config temp file already exists at {TEMP_CONF_PATH}, reuse it? (y/n)\n> "
                    );
                    io::stdin()
                        .read_line(&mut input)
                        .map_err(|e| warnx!("stdin: {e}"))?;
                    match input.trim() {
                        "y" | "Y" => {
                            eprintln!();
                            let temp_file = READ_OPTIONS.open(TEMP_CONF_PATH).map_err(|e| {
                                warnx!("open temp config file at {TEMP_CONF_PATH}: {e}");
                            })?;
                            // Ensure the reused temp file is securely owned by root and
                            // not accessible by other users before launching the editor.
                            c::fchown(temp_file.as_raw_fd(), 0, 0)
                                .map_err(|e| warnx!("fchown temp config file: {e}"))?;
                            let perm = Permissions::from_mode(0o0600);
                            temp_file
                                .set_permissions(perm)
                                .map_err(|e| warnx!("set temp config file mode: {e}"))?;
                            // NOTE:
                            // We return `None` here to signal that the existing temp file is being
                            // reused. This bypasses the subsequent `io::copy` to prevent overwriting.
                            // Concurrently, leaving `last_time` as `None` guarantees that
                            // `save_tmp_file` will always force an atomic rename upon exit, even if
                            // the file remains unmodified during the current editing session.
                            break None;
                        }
                        "n" | "N" => {
                            eprintln!();
                            remove_tmp_file()?;
                            break Some(create_options.open(TEMP_CONF_PATH).map_err(|e| {
                                warnx!("create temp file at {TEMP_CONF_PATH}: {e}");
                            })?);
                        }
                        _ => {
                            eprintln!();
                            input.clear();
                            continue;
                        }
                    }
                }
            }
            Err(e) => {
                errx!("create temp file at {TEMP_CONF_PATH}: {e}")
            }
        };
        let mut last_time = None;
        // Only set `last_time` if we created a fresh temp file.
        // For reused temp files (`None`), we skip this to preserve its current contents.
        if let Some(mut temp_file) = temp_file {
            io::copy(&mut conf_file, &mut temp_file)
                .map_err(|e| warnx!("copy config to temp file: {e}"))?;
            last_time = Some(Time(c::fstat(temp_file.as_raw_fd())?.st_mtime()));
            drop(temp_file);
        }
        let cmd_args = [TEMP_CONF_PATH];
        // Use xterm-256color for modern terminals (e.g., kitty) to prevent Vim E558 errors.
        if let Some(term) = envs.get_mut(OsStr::new("TERM")) {
            term.clear();
            term.push("xterm-256color");
        }
        'edit_loop: loop {
            let res = process::Command::new(cmd)
                .args(cmd_args.iter())
                .env_clear()
                .envs(envs.iter())
                .spawn();
            match res {
                Ok(mut child) => {
                    let exit_status = child.wait().map_err(|e| warnx!("child wait err: {e}"))?;
                    if !exit_status.success() {
                        errx!("editor exit abnormally");
                    }
                    match check_config(
                        Path::new(TEMP_CONF_PATH),
                        real_uid,
                        groups,
                        target_uid,
                        argvs,
                        true,
                        true,
                    ) {
                        Ok(()) => {
                            return save_tmp_file(&conf_file, last_time);
                        }
                        Err(err) => {
                            // The length of "FORCE_INVALID" must perfectly match
                            // "FORCE_LOCKOUT" (13 chars) for terminal UI alignment.
                            let confirm;
                            match err {
                                CheckErr::Config(err) => match err {
                                    ConfigError::Syntax(..) => {
                                        confirm = "FORCE_INVALID";
                                        eprintln!("vidoas: {err}");
                                        eprintln!(
                                            "\n--------------------------------------------------------------------------"
                                        );
                                        eprintln!(
                                            " WARNING: doas will completely FAIL to run with an invalid configuration."
                                        );
                                    }
                                    e => {
                                        errx!("{e}");
                                    }
                                },
                                CheckErr::Deny(rule) => {
                                    confirm = "FORCE_LOCKOUT";
                                    eprintln!(
                                        "vidoas: lockout detected! this configuration will revoke your access."
                                    );
                                    match rule {
                                        Some(rule) => {
                                            eprintln!("matched rule:");
                                            eprintln!("{}", ParsingConfig::from(*rule));
                                        }
                                        None => {
                                            eprintf!(
                                                "no matched rule for current user ('{}')\n",
                                                myname
                                            );
                                        }
                                    }
                                    eprintln!(
                                        "\n--------------------------------------------------------------------------"
                                    );
                                    eprintln!(
                                        " WARNING: You will LOSE the privilege to edit this config file again.",
                                    );
                                }
                            }
                            eprintln!(
                                "--------------------------------------------------------------------------"
                            );

                            let mut input = String::new();
                            loop {
                                eprintln!("Options:");
                                eprintln!("  e                - re-edit the file");
                                eprintln!("  x                - exit without saving");
                                eprintln!("  {confirm}    - save anyway (NOT RECOMMENDED)");
                                eprint!("\n> ");
                                io::stdin()
                                    .read_line(&mut input)
                                    .map_err(|e| warnx!("stdin: {e}"))?;
                                match input.trim() {
                                    "e" => {
                                        eprintln!();
                                        continue 'edit_loop;
                                    }
                                    "x" => {
                                        return remove_tmp_file();
                                    }
                                    // User explicitly acknowledged the risk by typing the exact
                                    // protection word. Proceed to overwrite anyway.
                                    word if word == confirm => {
                                        return save_tmp_file(&conf_file, last_time);
                                    }
                                    _ => {
                                        eprintln!();
                                        input.clear();
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    errx!("{:?}: command not found", cmd);
                }
                Err(e) => {
                    errx!("process spawn failed: {e}");
                }
            }
        }
    }
}

fn save_tmp_file(conf_file: &File, last_time: Option<Time>) -> Result<(), ()> {
    let temp_file = READ_OPTIONS
        .open(TEMP_CONF_PATH)
        .map_err(|e| warnx!("open temp config file at {TEMP_CONF_PATH}: {e}"))?;
    let origin_stat = c::fstat(conf_file.as_raw_fd())?;
    let temp_stat = c::fstat(temp_file.as_raw_fd())?;
    let new_time = Time(temp_stat.st_mtime());
    // return early if the user exited the editor without modifying any rules.
    if last_time == Some(new_time) {
        println!("vidoas: {TEMP_CONF_PATH} unchanged");
        fs::remove_file(TEMP_CONF_PATH)
            .map_err(|e| warnx!("remove temp file at {TEMP_CONF_PATH}: {e}"))?;
        return Ok(());
    }
    // Restore the original ownership and file mode flags.
    c::fchown(
        temp_file.as_raw_fd(),
        origin_stat.st_uid,
        origin_stat.st_gid,
    )
    .map_err(|e| warnx!("fchown temp config file: {e}"))?;
    let perm = Permissions::from_mode(origin_stat.st_mode as u32);
    temp_file
        .set_permissions(perm)
        .map_err(|e| warnx!("set temp config file mode: {e}"))?;
    drop(temp_file);
    // Perform an atomic replacement within the same file system boundary.
    // This ensures `/etc/doas.conf` is never left in a partially-written or corrupt state.
    fs::rename(TEMP_CONF_PATH, CONF_PATH)
        .map_err(|e| warnx!("rename {TEMP_CONF_PATH} to {CONF_PATH}: {e}"))?;
    println!("vidoas: {CONF_PATH} updated successfully.");
    Ok(())
}

fn remove_tmp_file() -> Result<(), ()> {
    fs::remove_file(TEMP_CONF_PATH).map_err(|e| warnx!("remove temp file at {TEMP_CONF_PATH}: {e}"))
}
