use libc::{gid_t, uid_t};
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    fmt::{self, Display},
    fs,
    io::{self, Read as _},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, PermissionsExt as _},
    },
    path::Path,
    time::Duration,
};

use crate::{
    c, errx, gen_tokenizer,
    timestamp::FromStr as _,
    tokenizer::{State, Tokenizer},
};

#[derive(Debug)]
pub enum ConfigError<'a> {
    IO(io::Error, &'a Path),
    Permission(&'static str, &'a Path),
    Syntax(Cow<'static, str>, usize, Box<ParsingConfig>),
}

impl<'a> ConfigError<'a> {
    fn syntax(err: Cow<'static, str>, line: usize, config: ParsingConfig) -> Self {
        Self::Syntax(err, line, Box::new(config))
    }
}

impl<'a> fmt::Display for ConfigError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(e, path) => writeln!(f, "IO: {e}, file path: {}", path.display()),
            Self::Permission(e, path) => {
                writeln!(f, "permission: {e}, file path: {}", path.display())
            }
            Self::Syntax(e, line, parsing_config) => writeln!(
                f,
                "syntax: line {line}: {e}\nwhile parsing rule:\n\n{}",
                parsing_config
            ),
        }
    }
}

impl<'a> std::error::Error for ConfigError<'a> {}

#[derive(Debug, Clone, Copy)]
pub enum Action {
    Permit,
    Deny,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Env {
    Keep(String),
    Remove(String),
    Set { key: String, val: Val },
}

impl Display for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Env::Keep(_) | Env::Remove(_) => write!(f, "{:?}", self),
            Env::Set { key, val } => write!(f, "Set(\"{}\"={:?})", key, val),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Val {
    New(String),
    FromEnv(String),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub nopass: bool,
    pub pwfeedback: bool,
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

impl Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(_) | Self::Group(_) => write!(f, "{:?}", self),
            Self::Both { user, group } => write!(f, "User(\"{}\"), Group(\"{}\")", user, group),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    action: Action,
    pub options: Options,
    identity: Identity,
    target: Option<String>,
    cmd: Option<Cmd>,
}

#[derive(Debug, Default)]
pub struct ParsingConfig {
    action: Option<Action>,
    options: Options,
    identity: Option<Identity>,
    target: Option<String>,
    cmd: Option<Cmd>,
}

impl From<Config> for ParsingConfig {
    fn from(value: Config) -> Self {
        Self {
            action: Some(value.action),
            options: value.options,
            identity: Some(value.identity),
            target: value.target,
            cmd: value.cmd,
        }
    }
}

impl Display for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.nopass {
            write!(f, "nopass ")?;
        }
        if self.pwfeedback {
            write!(f, "pwfeedback ")?;
        }
        if self.insult {
            write!(f, "insult ")?;
        }
        if self.nolog {
            write!(f, "nolog ")?;
        }
        if self.keepenv {
            write!(f, "keepenv ")?;
        }
        if let Some(dur) = self.persist {
            write!(f, "persist {{{:?}}} ", dur)?;
        }
        if !self.envs.is_empty() {
            write!(f, "setenv\nenvs: {{ ")?;
            for env in self.envs.iter() {
                write!(f, "{env} ")?;
            }
            write!(f, "}}")?;
        }
        Ok(())
    }
}

impl Display for ParsingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "action: ")?;
        match self.action {
            Some(action) => writeln!(f, "{:?}", action)?,
            None => writeln!(f, "None")?,
        }

        if self.options != Options::default() {
            writeln!(f, "options: {}", self.options)?;
        }

        write!(f, "identity: ")?;
        match &self.identity {
            Some(identity) => writeln!(f, "{}", identity)?,
            None => writeln!(f, "None")?,
        }

        if let Some(target) = &self.target {
            writeln!(f, "target: {}", target)?;
        }
        if let Some(cmd) = &self.cmd {
            writeln!(f, "cmd: {}", cmd.cmd)?;
            if let Some(args) = &cmd.cmd_args {
                writeln!(f, "args: {:?}", args)?;
            }
        }
        Ok(())
    }
}

static DEFAULT_TIMEOUT: Duration = Duration::from_mins(5);

fn parser<'a, T>(tokens: &mut Tokenizer<T>) -> Result<Config, ConfigError<'a>>
where
    T: Iterator<Item = State>,
{
    let mut parsing_config = ParsingConfig::default();
    // there must be an action
    let action = match tokens.next() {
        Some(s) if s.is_key("permit") => Action::Permit,
        Some(s) if s.is_key("deny") => Action::Deny,
        _ => {
            return Err(ConfigError::syntax(
                "missing action".into(),
                tokens.line(),
                parsing_config,
            ));
        }
    };
    parsing_config.action = Some(action);

    // optional options
    'outer: loop {
        match tokens.peek() {
            Some(token) if !token.quoted() => match token.as_str() {
                "nopass" => {
                    parsing_config.options.nopass = true;
                    tokens.next();
                }
                "nolog" => {
                    parsing_config.options.nolog = true;
                    tokens.next();
                }
                "persist" => {
                    tokens.next();
                    if let Some(s) = tokens.peek()
                        && s.is_key("{")
                    {
                        tokens.next();
                        let Some(duration) = tokens.next() else {
                            return Err(ConfigError::syntax(
                                "missing duration after \"persist { \"".into(),
                                tokens.line(),
                                parsing_config,
                            ));
                        };
                        match Duration::from_str(duration.as_str()) {
                            Ok(dur) => parsing_config.options.persist = Some(dur),
                            Err(e) => {
                                return Err(ConfigError::syntax(
                                    e.into(),
                                    tokens.line(),
                                    parsing_config,
                                ));
                            }
                        }
                        if let Some(s) = tokens.next()
                            && !s.is_key("}")
                        {
                            return Err(ConfigError::syntax(
                                "missing \"}\" after duration".into(),
                                tokens.line(),
                                parsing_config,
                            ));
                        }
                    } else {
                        parsing_config.options.persist = Some(DEFAULT_TIMEOUT);
                    }
                }
                "pwfeedback" => {
                    parsing_config.options.pwfeedback = true;
                    tokens.next();
                }
                "keepenv" => {
                    parsing_config.options.keepenv = true;
                    tokens.next();
                }
                "insult" => {
                    parsing_config.options.insult = true;
                    tokens.next();
                }
                "setenv" => {
                    tokens.next();
                    if tokens.next().is_none_or(|s| !s.is_key("{")) {
                        return Err(ConfigError::syntax(
                            "missing envs after \"setenv\"".into(),
                            tokens.line(),
                            parsing_config,
                        ));
                    }
                    while let Some(token) = tokens.next() {
                        if token.is_key("}") {
                            if parsing_config.options.envs.is_empty() {
                                return Err(ConfigError::syntax(
                                    "missing envs inside \"{}\"".into(),
                                    tokens.line(),
                                    parsing_config,
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
                                return Err(ConfigError::syntax(
                                    format!(
                                        "invalid env: {}, missing an env after \"-\"",
                                        token.as_str()
                                    )
                                    .into(),
                                    tokens.line(),
                                    parsing_config,
                                ));
                            }
                            parsing_config
                                .options
                                .envs
                                .push(Env::Remove(env.to_owned()));
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
                                return Err(ConfigError::syntax(
                                    format!(
                                        "invalid env: {}, missing a key before \"=\"",
                                        token.as_str()
                                    )
                                    .into(),
                                    tokens.line(),
                                    parsing_config,
                                ));
                            }
                            let (key, val) = token
                                .as_str()
                                .split_once("=")
                                .expect("we have checked before");

                            if val.is_empty() {
                                return Err(ConfigError::syntax(
                                    format!(
                                        "invalid env: {}, missing a value after \"=\"",
                                        token.as_str()
                                    )
                                    .into(),
                                    tokens.line(),
                                    parsing_config,
                                ));
                            }
                            let val = match val_unquote.split_once("$") {
                                Some(("", "")) => {
                                    return Err(ConfigError::syntax(
                                        "missing env name after \"$\"".into(),
                                        tokens.line(),
                                        parsing_config,
                                    ));
                                }
                                Some(("", value)) => Val::FromEnv(value.to_owned()),
                                _ => Val::New(val.to_owned()),
                            };
                            parsing_config.options.envs.push(Env::Set {
                                key: key.to_owned(),
                                val,
                            });
                        } else if !token.quoted() {
                            parsing_config
                                .options
                                .envs
                                .push(Env::Keep(token.into_string()));
                        } else {
                            eprintln!("warning: quoted env: \"{}\" is ignored", token.as_str());
                        }
                    }
                    return Err(ConfigError::syntax(
                        "missing \"}\" after envs".into(),
                        tokens.line(),
                        parsing_config,
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
                return Err(ConfigError::syntax(
                    "missing identity".into(),
                    tokens.line(),
                    parsing_config,
                ));
            }
        }
    }

    // there must be an identity
    let identity_str = match tokens.next() {
        Some(i) => i.into_string(),
        _ => {
            return Err(ConfigError::syntax(
                "missing identity".into(),
                tokens.line(),
                parsing_config,
            ));
        }
    };
    let identity = match identity_str.split_once(":") {
        Some((user, group)) => {
            if !user.is_empty() && !group.is_empty() {
                Identity::Both {
                    user: user.to_owned(),
                    group: group.to_owned(),
                }
            } else if !group.is_empty() {
                Identity::Group(group.to_owned())
            } else if !user.is_empty() {
                Identity::User(identity_str)
            } else {
                return Err(ConfigError::syntax(
                    "missing identity".into(),
                    tokens.line(),
                    parsing_config,
                ));
            }
        }
        None => Identity::User(identity_str),
    };
    parsing_config.identity = Some(identity);

    // optional target
    parsing_config.target = if let Some(token) = tokens.peek()
        && token.is_key("as")
    {
        tokens.next();
        // parse target
        match tokens.next() {
            Some(target) => Some(target.into_string()),
            None => {
                return Err(ConfigError::syntax(
                    "missing target after \"as\"".into(),
                    tokens.line(),
                    parsing_config,
                ));
            }
        }
    } else {
        None
    };

    // optional cmd
    if let Some(token) = tokens.next() {
        if !token.is_key("cmd") {
            return Err(ConfigError::syntax(
                "expected \"cmd\" before command".into(),
                tokens.line(),
                parsing_config,
            ));
        }
        let cmd = match tokens.next() {
            Some(s) => s.into_string(),
            None => {
                return Err(ConfigError::syntax(
                    "missing command after \"cmd\"".into(),
                    tokens.line(),
                    parsing_config,
                ));
            }
        };
        let cmd = Cmd {
            cmd,
            cmd_args: None,
        };
        let cmd = parsing_config.cmd.insert(cmd);
        // optional args
        if let Some(arg) = tokens.next() {
            if arg.is_key("args") {
                let args = tokens.by_ref().map(|t| t.into_string()).collect();
                cmd.cmd_args = Some(args);
            } else {
                return Err(ConfigError::syntax(
                    "expected \"args\" after command".into(),
                    tokens.line(),
                    parsing_config,
                ));
            }
        }
    }

    let config = Config {
        action,
        options: parsing_config.options,
        identity: parsing_config.identity.expect("identity is set before"),
        target: parsing_config.target,
        cmd: parsing_config.cmd,
    };

    Ok(config)
}

#[cfg_attr(miri, ignore = "miri doesn't support IO operation")]
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
        match Config::parse(&file.path(), false) {
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
    pub fn parse<'a>(path: &'a Path, check_perm: bool) -> Result<Vec<Config>, ConfigError<'a>> {
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

    pub fn has_cmd(&self) -> bool {
        self.cmd.is_some()
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
    path: &Path,
    uid: uid_t,
    groups: &[gid_t],
    target: uid_t,
    cmds: &[OsString],
    verbose: bool,
) -> Result<(), ()> {
    // downgrade to real uid.
    c::setreuid(uid, uid)?;
    let rules = match Config::parse(path, false) {
        Ok(c) => c,
        Err(e) => errx!("config error: {e}"),
    };
    if cmds.is_empty() {
        println!("the configuration file syntax is ok");
        if verbose {
            println!("parsed config:\n");
            for rule in rules {
                println!("{}", ParsingConfig::from(rule));
            }
        }
        return Ok(());
    }

    let mut last_rule = None;
    for rule in rules {
        if rule
            .match_rule(uid, groups, target, &cmds[0], &cmds[1..])
            .is_ok()
        {
            last_rule = Some(rule);
        }
    }

    let result;
    if let Some(r) = last_rule {
        if matches!(r.action, Action::Permit) {
            println!("permit{}", if r.options.nopass { " nopass" } else { "" });
            result = Ok(());
        } else {
            println!("deny");
            result = Err(());
        }
        if verbose {
            println!("matched rule:\n");
            println!("{}", ParsingConfig::from(r));
        }
    } else {
        println!("deny");
        result = Err(());

        if verbose {
            println!("no matched rule");
        }
    }

    result
}
