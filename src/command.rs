use crate::{VERSION, list_features, warnx};
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt as _, OsStringExt as _},
    process,
};

#[derive(Default, Debug)]
pub struct CmdArgs {
    /// Config path
    ///
    /// Parse and check the configuration file config, then exit. If command is supplied,
    /// doas will also perform command matching. In the latter case either ‘permit’,
    /// ‘permit nopass’ or ‘deny’ will be printed on standard output, depending on
    /// command matching results. No command is executed.
    pub config: Option<OsString>,

    pub vidoas: bool,

    pub verbose: bool,

    /// User name or uid
    ///
    /// Execute the command as user. The default is root.
    pub user: Option<String>,

    /// Non interactive mode, fail if the matching rule doesn't have the nopass option.
    pub non_interactive: bool,

    /// Execute the shell from SHELL or /etc/passwd.
    pub shell: bool,

    /// Clear any persisted authentications from previous invocations, then immediately
    /// exit. No command is executed.
    pub clear: bool,

    /// Command to run
    pub command: Vec<OsString>,
}

macro_rules! usage {
    () => {
        usage();
        return Err(());
    };
}

#[inline]
fn usage() {
    eprintln!("usage: doas [--version] [-Lnsv] [-C config] [-u user] command [arg ...]");
}

impl CmdArgs {
    pub fn parse() -> Result<Self, ()> {
        let mut args = std::env::args_os().peekable();
        // ignore program name
        args.next();
        if args.peek().is_none() {
            usage!();
        }
        let mut parsed = Self::default();
        while let Some(arg) = args.peek() {
            if arg.is_empty() {
                args.next();
                continue;
            }
            match arg.as_bytes() {
                b"--" => {
                    // skip "--"
                    args.next();
                    // pass values directly
                    parsed.extend_cmds(args)?;
                    break;
                }
                b"--version" => {
                    println!("doas {}", VERSION);
                    list_features!("apple-auth", "nightly");
                    process::exit(0);
                }
                b"vidoas" => {
                    args.next();
                    parsed.vidoas = true;
                }
                [b'-', _] => {
                    let option = args.next().unwrap().as_bytes()[1];
                    let mut next_arg = args.peek_mut();
                    parsed.handle_option(option, &mut next_arg)?;
                }
                [b'-', ..] => {
                    let options = args.next().unwrap().into_vec();
                    let mut next_arg = args.peek_mut();
                    for &option in &options[1..] {
                        parsed.handle_option(option, &mut next_arg)?;
                    }
                }
                _ => {
                    // no option matches, pass values directly
                    parsed.extend_cmds(args)?;
                    break;
                }
            }
        }

        // check conflicts
        if parsed.clear
            && (!parsed.command.is_empty()
                || parsed.shell
                || parsed.user.is_some()
                || parsed.config.is_some()
                || parsed.non_interactive
                || parsed.verbose)
        {
            eprintln!("'-L' cannot be used with other options or commands");
            usage!();
        }

        if parsed.vidoas
            && (!parsed.command.is_empty()
                || parsed.shell
                || parsed.clear
                || parsed.user.is_some()
                || parsed.config.is_some()
                || parsed.non_interactive
                || parsed.verbose)
        {
            eprintln!("'vidoas' cannot be used with other options or commands");
            usage!();
        }
        if parsed.verbose && parsed.config.is_none() {
            eprintln!("'-v' requires '-C'");
            usage!();
        }
        if parsed.config.is_some()
            && (parsed.shell || parsed.non_interactive || parsed.user.is_some())
        {
            eprintln!("'-C' is conflicted with '-u', '-s', '-n'");
            usage!();
        }

        if !parsed.vidoas
            && !parsed.shell
            && !parsed.clear
            && parsed.config.is_none()
            && parsed.command.is_empty()
        {
            eprintln!("missing command");
            usage!();
        }

        Ok(parsed)
    }

    fn handle_option(
        &mut self,
        option: u8,
        next_arg: &mut Option<&mut OsString>,
    ) -> Result<(), ()> {
        match option {
            b's' => {
                if self.shell {
                    eprintln!("'-s' cannot be used multiple times");

                    usage!();
                }
                self.shell = true;
            }
            b'n' => {
                if self.non_interactive {
                    eprintln!("'-n' cannot be used multiple times");

                    usage!();
                }
                self.non_interactive = true;
            }
            b'L' => {
                if self.clear {
                    eprintln!("'-L' cannot be used multiple times");

                    usage!();
                }
                self.clear = true;
            }
            b'v' => {
                if self.verbose {
                    eprintln!("'-v' cannot be used multiple times");

                    usage!();
                }
                self.verbose = true;
            }
            b'u' => {
                if self.user.is_some() {
                    eprintln!("argument 'user' cannot be used multiple times");

                    usage!();
                }
                let user = next_arg.take().ok_or_else(|| {
                    eprintln!("missing 'user' after '-u'");
                    usage();
                })?;
                let user = std::mem::take(user);
                let user = user
                    .into_string()
                    .map_err(|_| warnx!("argument 'user' needs to be utf-8 encoded"))?;
                self.user = Some(user);
            }
            b'C' => {
                if self.config.is_some() {
                    eprintln!("argument 'config' cannot be used multiple times");
                    usage!();
                }
                let path = next_arg.take().ok_or_else(|| {
                    eprintln!("missing 'config' after '-C'");
                    usage();
                })?;
                let path = std::mem::take(path);
                self.config = Some(path);
            }
            other => {
                eprintln!("invalid option: '{}'", other as char);
                usage!();
            }
        }
        Ok(())
    }

    fn extend_cmds(&mut self, args: impl Iterator<Item = OsString>) -> Result<(), ()> {
        if self.shell {
            eprintln!("'-s' cannot be used with command");
            usage!();
        }
        if self.clear {
            eprintln!("'-L' cannot be used with command");
            usage!();
        }
        self.command.extend(args);
        Ok(())
    }
}
