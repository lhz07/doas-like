use libc::{gid_t, uid_t};
use std::{
    borrow::Cow,
    collections::HashSet,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    sync::LazyLock,
    time::Duration,
};

use crate::{
    c, errx, gen_tokenizer,
    timestamp::FromStr,
    tokenizer::{State, Tokenizer},
};

#[derive(Debug)]
pub enum ConfigError<'a> {
    IO(io::Error, &'a str),
    Permission(&'static str, &'a str),
    Syntax(Cow<'static, str>, usize),
}

impl<'a> fmt::Display for ConfigError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(e, path) => writeln!(f, "{e}, file path: {path}")?,
            Self::Permission(e, path) => writeln!(f, "permission: {e}, file path: {path}")?,
            Self::Syntax(e, line) => writeln!(f, "syntax: line {line}: {e}")?,
        }
        Ok(())
    }
}

impl<'a> std::error::Error for ConfigError<'a> {}

#[derive(Debug)]
pub enum Action {
    Permit,
    Deny,
}

#[derive(Debug)]
pub enum Env {
    Keep(String),
    Remove(String),
    Set { key: String, val: Val },
}

#[derive(Debug)]
pub enum Val {
    New(String),
    FromEnv(String),
}

#[derive(Debug, Default)]
pub struct Options {
    pub nopass: bool,
    pub insult: bool,
    pub nolog: bool,
    pub persist: Option<Duration>,
    pub keepenv: bool,
    pub envs: Vec<Env>,
}

#[derive(Debug)]
pub struct Cmd {
    cmd: String,
    cmd_args: Option<Vec<String>>,
}

#[derive(Debug)]
pub enum Identity {
    User(String),
    Group(String),
    Both { user: String, group: String },
}

#[derive(Debug)]
pub struct Config {
    action: Action,
    pub options: Options,
    identity: Identity,
    target: Option<String>,
    cmd: Option<Cmd>,
}

static OPTIONS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["nopass", "nolog", "persist", "keepenv", "insult", "setenv"]
        .into_iter()
        .collect()
});
static DEFAULT_TIMEOUT: Duration = Duration::from_mins(5);

fn parser<'a, T>(tokens: &mut Tokenizer<T>) -> Result<Config, ConfigError<'a>>
where
    T: Iterator<Item = State>,
{
    // let mut tokens = tokens.into_iter().peekable();

    // there must be an action
    let action = match tokens.next() {
        Some(s) if s.is_key("permit") => Action::Permit,
        Some(s) if s.is_key("deny") => Action::Deny,
        _ => return Err(ConfigError::Syntax("missing action".into(), tokens.line())),
    };

    // optional options
    let mut options = Options::default();
    let mut available_options = OPTIONS.clone();
    'outer: loop {
        match tokens.peek() {
            Some(token) if !token.quoted() => match token.as_str() {
                "nopass" => {
                    if !available_options.remove("nopass") {
                        return Err(ConfigError::Syntax(
                            "duplicate \"nopass\"".into(),
                            tokens.line(),
                        ));
                    }
                    options.nopass = true;
                    tokens.next();
                }
                "nolog" => {
                    options.nolog = true;
                    tokens.next();
                }
                "persist" => {
                    if !available_options.remove("persist") {
                        return Err(ConfigError::Syntax(
                            "duplicate \"persist\"".into(),
                            tokens.line(),
                        ));
                    }
                    tokens.next();
                    if let Some(s) = tokens.peek()
                        && s.is_key("{")
                    {
                        tokens.next();
                        let Some(duration) = tokens.next() else {
                            return Err(ConfigError::Syntax(
                                "missing duration after \"persist { \"".into(),
                                tokens.line(),
                            ));
                        };
                        match Duration::from_str(duration.as_str()) {
                            Ok(dur) => options.persist = Some(dur),
                            Err(e) => {
                                return Err(ConfigError::Syntax(e.into(), tokens.line()));
                            }
                        }
                        if let Some(s) = tokens.next()
                            && !s.is_key("}")
                        {
                            return Err(ConfigError::Syntax(
                                "missing \"}\" after duration".into(),
                                tokens.line(),
                            ));
                        }
                    } else {
                        options.persist = Some(DEFAULT_TIMEOUT);
                    }
                }
                "keepenv" => {
                    options.keepenv = true;
                    tokens.next();
                }
                "insult" => {
                    options.insult = true;
                    tokens.next();
                }
                "setenv" => {
                    tokens.next();
                    if tokens.next().is_none_or(|s| !s.is_key("{")) {
                        return Err(ConfigError::Syntax(
                            "missing envs after \"setenv\"".into(),
                            tokens.line(),
                        ));
                    }
                    while let Some(token) = tokens.next() {
                        if token.is_key("}") {
                            if options.envs.is_empty() {
                                return Err(ConfigError::Syntax(
                                    "missing envs inside \"{}\"".into(),
                                    tokens.line(),
                                ));
                            }
                            continue 'outer;
                        } else if !token.quoted()
                            && let Some((nothing, env)) = token.as_str().split_once("-")
                            && nothing.is_empty()
                        {
                            // the environment variable only allows letters, numbers and "_"
                            // Examples:
                            // -PKG
                            // -PKG_CACHE
                            // -PKG_CACHE_2
                            if env.is_empty() {
                                return Err(ConfigError::Syntax(
                                    format!(
                                        "invalid env: {}, missing an env after \"-\"",
                                        token.as_str()
                                    )
                                    .into(),
                                    tokens.line(),
                                ));
                            }
                            options.envs.push(Env::Remove(env.to_string()));
                        }
                        // PKG="/path/to"
                        // PKG=/path"/to"
                        // PKG="/path"/to
                        // PKG=/path/to
                        // PKG="jUh38aS$"
                        // PKG=jUh38"aS$"
                        // PKG=$PHG_CACHE
                        else if let Some((key, val_unquote)) =
                            token.before_quoted().split_once("=")
                        {
                            if key.is_empty() {
                                return Err(ConfigError::Syntax(
                                    format!(
                                        "invalid env: {}, missing a key before \"=\"",
                                        token.as_str()
                                    )
                                    .into(),
                                    tokens.line(),
                                ));
                            }
                            let (key, val) = token
                                .as_str()
                                .split_once("=")
                                .expect("we have checked before");

                            if val.is_empty() {
                                return Err(ConfigError::Syntax(
                                    format!(
                                        "invalid env: {}, missing a value after \"=\"",
                                        token.as_str()
                                    )
                                    .into(),
                                    tokens.line(),
                                ));
                            }
                            let val = match val_unquote.split_once("$") {
                                Some(("", "")) => {
                                    return Err(ConfigError::Syntax(
                                        "missing env name after \"$\"".into(),
                                        tokens.line(),
                                    ));
                                }
                                Some(("", value)) => Val::FromEnv(value.to_string()),
                                _ => Val::New(val.to_string()),
                            };
                            options.envs.push(Env::Set {
                                key: key.to_string(),
                                val,
                            });
                        } else if !token.quoted() {
                            options.envs.push(Env::Keep(token.into_string()));
                        } else {
                            eprintln!("warning: quoted env: \"{}\" is ignored", token.as_str())
                        }
                    }
                    return Err(ConfigError::Syntax(
                        "missing \"}\" after envs".into(),
                        tokens.line(),
                    ));
                }
                _ => {
                    // no options, we should parse user
                    break;
                }
            },
            Some(_) => {
                // no options, we should parse user
                break;
            }
            None => {
                return Err(ConfigError::Syntax(
                    "missing identity".into(),
                    tokens.line(),
                ));
            }
        }
    }

    // there must be an identity
    let identity = match tokens.next() {
        Some(i) => i.into_string(),
        _ => {
            return Err(ConfigError::Syntax(
                "missing identity".into(),
                tokens.line(),
            ));
        }
    };
    let identity = match identity.split_once(":") {
        Some((user, group)) => {
            if !user.is_empty() && !group.is_empty() {
                Identity::Both {
                    user: user.to_string(),
                    group: group.to_string(),
                }
            } else if !group.is_empty() {
                Identity::Group(group.to_string())
            } else if !user.is_empty() {
                Identity::User(identity)
            } else {
                return Err(ConfigError::Syntax(
                    "missing identity".into(),
                    tokens.line(),
                ));
            }
        }
        None => Identity::User(identity),
    };

    // optional target
    let target = if let Some(token) = tokens.peek()
        && token.is_key("as")
    {
        tokens.next();
        // parse target
        match tokens.next() {
            Some(target) => Some(target.into_string()),
            None => {
                return Err(ConfigError::Syntax(
                    "missing target after \"as\"".into(),
                    tokens.line(),
                ));
            }
        }
    } else {
        None
    };

    // optional cmd
    let cmd = if let Some(token) = tokens.next() {
        if !token.is_key("cmd") {
            return Err(ConfigError::Syntax(
                "expected \"cmd\" before command".into(),
                tokens.line(),
            ));
        }
        let cmd = match tokens.next() {
            Some(s) => s.into_string(),
            None => {
                return Err(ConfigError::Syntax(
                    "missing command after \"cmd\"".into(),
                    tokens.line(),
                ));
            }
        };
        // optional args
        let cmd_args = match tokens.next() {
            Some(arg) => {
                if arg.is_key("args") {
                    let args = tokens.by_ref().map(|t| t.into_string()).collect();
                    Some(args)
                } else {
                    return Err(ConfigError::Syntax(
                        "expected \"args\" after command".into(),
                        tokens.line(),
                    ));
                }
            }
            None => None,
        };
        Some(Cmd { cmd, cmd_args })
    } else {
        None
    };

    let config = Config {
        action,
        options,
        identity,
        target,
        cmd,
    };

    Ok(config)
}

#[test]
fn test_parse() {
    #[cfg(feature = "nightly")]
    println!("with nightly feature");
    #[cfg(not(feature = "nightly"))]
    println!("without nightly feature");

    let files = fs::read_dir("tests").unwrap();
    for file in files {
        let file = file.unwrap();
        if !file.file_name().to_string_lossy().starts_with("test") {
            continue;
        }
        match Config::parse(file.path().to_string_lossy().as_ref(), false) {
            Ok(rules) => println!(
                "file name: {}, rules: {:?}\n",
                file.file_name().display(),
                rules
            ),
            Err(e) => panic!("file name: {}, error: {e}", file.file_name().display()),
        }
    }
}

fn check_uid(uid: uid_t, desired: &str) -> Result<(), ()> {
    let desired = c::parse_uid(desired)?;
    if desired == uid { Ok(()) } else { Err(()) }
}

impl Config {
    pub fn parse(path: &str, check_perm: bool) -> Result<Vec<Config>, ConfigError<'_>> {
        let mut file = fs::File::open(path).map_err(|e| ConfigError::IO(e, path))?;
        if check_perm {
            // check file permission
            let meta = file.metadata().map_err(|e| ConfigError::IO(e, path))?;
            // don't forget to mask out file type bits
            // file type | special | permission
            //    010    |    0    |    644
            if (meta.permissions().mode() & 0o777) != 0o0644 {
                return Err(ConfigError::Permission(
                    "config file is writable by group or other",
                    path,
                ));
            }
            if meta.uid() != 0 {
                return Err(ConfigError::Permission(
                    "config file is not owned by root",
                    path,
                ));
            }
        }

        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| ConfigError::IO(e, path))?;
        let mut rules = Vec::new();
        gen_tokenizer!(tokenizer, &content);

        while tokenizer.next_line() {
            let rule = parser(&mut tokenizer)?;
            rules.push(rule);
        }
        Ok(rules)
    }

    pub fn match_rule(
        &self,
        uid: uid_t,
        groups: &[gid_t],
        target: uid_t,
        cmd: &OsStr,
        cmd_args: &[OsString],
    ) -> Result<(), ()> {
        let rule = self;
        // check identity
        match &rule.identity {
            Identity::User(user) => {
                check_uid(uid, user)?;
            }
            Identity::Group(group) => {
                let gid = c::parse_gid(group)?;
                let mut res = Err(());
                for g in groups {
                    if *g == gid {
                        res = Ok(());
                        break;
                    }
                }
                res?;
            }
            Identity::Both { user, group } => {
                check_uid(uid, user)?;
                let gid = c::parse_gid(group)?;
                let mut res = Err(());
                for g in groups {
                    if *g == gid {
                        res = Ok(());
                        break;
                    }
                }
                res?;
            }
        }

        if let Some(tar) = &rule.target {
            check_uid(target, tar)?;
        }

        if let Some(command) = &rule.cmd {
            if cmd.as_bytes() != command.cmd.as_bytes() {
                return Err(());
            }
            if let Some(args) = &command.cmd_args {
                if args.len() != cmd_args.len() {
                    return Err(());
                }
                for (arg, cmd_arg) in args.iter().zip(cmd_args) {
                    if arg.as_bytes() != cmd_arg.as_bytes() {
                        return Err(());
                    }
                }
            }
        }

        Ok(())
    }
}

#[must_use = "you should always check this"]
pub fn permit(
    rules: Vec<Config>,
    uid: uid_t,
    groups: &[gid_t],
    target: uid_t,
    cmd: &OsStr,
    cmd_args: &[OsString],
) -> Option<Config> {
    let mut last_rule = None;
    for rule in rules {
        if rule.match_rule(uid, groups, target, cmd, cmd_args).is_ok() {
            last_rule = Some(rule);
        }
    }

    last_rule.and_then(|r| {
        if matches!(r.action, Action::Permit) {
            Some(r)
        } else {
            None
        }
    })
}

pub fn check_config(
    path: &str,
    uid: uid_t,
    groups: &[gid_t],
    target: uid_t,
    cmds: &[OsString],
) -> Result<(), ()> {
    let rules = match Config::parse(path, false) {
        Ok(c) => c,
        Err(e) => errx!("config error: {e}"),
    };
    if cmds.is_empty() {
        println!("the configuration file syntax is ok");
        return Ok(());
    }
    if let Some(r) = permit(rules, uid, groups, target, &cmds[0], &cmds[1..]) {
        println!("permit{}", if r.options.nopass { " nopass" } else { "" });
        Ok(())
    } else {
        println!("deny");
        Err(())
    }
}
