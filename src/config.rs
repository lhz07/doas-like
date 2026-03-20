use libc::{gid_t, uid_t};
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{self, Read},
    iter::Peekable,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    str::Chars,
};

use crate::{c, errx};

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
            Self::Syntax(e, line) => writeln!(f, "syntax: {e} at line: {line}")?,
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
    nolog: bool,
    persist: bool,
    keepenv: bool,
    envs: Vec<Env>,
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

// #[derive(Debug, Clone, Copy)]
// enum ParseState {
//     Action,
//     Options,
//     User,
//     Cmd,
//     CmdArgs,
// }

// impl ParseState {
//     fn new() -> Self {
//         Self::Action
//     }
//     fn next(&mut self) {
//         let new = match self {
//             Self::Action => Self::Options,
//             Self::Options => Self::User,
//             Self::User => Self::Cmd,
//             Self::Cmd => Self::CmdArgs,
//             Self::CmdArgs => return,
//         };
//         *self = new;
//     }
// }

// fn parse_config(path: &str) -> Result<Vec<Config>, ConfigError> {
//     let content = fs::read_to_string(path)?;
//     let mut rules = Vec::new();
//     let lines = content.lines();
//     for l in lines.clone() {
//         println!("{:?}", tokenizer(l));
//     }
//     for line in lines {
//         let rule = parse_line(line)?;
//         rules.push(rule);
//     }
//     Ok(rules)
// }

// fn parse_line(line: &str) -> Result<Config, ConfigError> {
//     let mut config = Config::default();
//     let mut state = ParseState::new();
//     let mut str = String::new();
//     let line_chars = line.chars();
//     let space = " ".chars();
//     // let mut finished = false;
//     let mut parsing_env = false;
//     let mut parsing_target = false;
//     let mut skip_iter = false;
//     let mut chars = line_chars.chain(space);
//     loop {
//         if !skip_iter {
//             if let Some(ch) = chars.next() {
//                 if !ch.is_whitespace() {
//                     str.push(ch);
//                     continue;
//                 }
//             } else {
//                 break;
//             }
//         } else {
//             skip_iter = false;
//         }
//         match state {
//             ParseState::Action => match str.as_str() {
//                 "deny" => {
//                     config.action = Action::Deny;
//                     state.next();
//                     str.clear();
//                 }
//                 "permit" => {
//                     config.action = Action::Permit;
//                     state.next();
//                     str.clear();
//                 }

//                 _ => return Err(ConfigError::Format("missing action".into())),
//             },
//             ParseState::Options => match str.as_str() {
//                 "nopass" => {
//                     let options = config.options.get_or_insert(Options::default());
//                     options.nopass = true;
//                     str.clear();
//                 }
//                 "nolog" => {
//                     let options = config.options.get_or_insert(Options::default());
//                     options.nolog = true;
//                     str.clear();
//                 }
//                 "persist" => {
//                     let options = config.options.get_or_insert(Options::default());
//                     options.persist = true;
//                     str.clear();
//                 }
//                 "keepenv" => {
//                     let options = config.options.get_or_insert(Options::default());
//                     options.keepenv = true;
//                     str.clear();
//                 }
//                 "setenv" => {
//                     let options = config.options.get_or_insert(Options::default());
//                 }
//                 "{" => {
//                     parsing_env = true;
//                     str.clear();
//                 }
//                 "}" => {
//                     parsing_env = false;
//                     str.clear();
//                 }
//                 _ if parsing_env => {}
//                 // _ if config.options.is_none() => {
//                 //     // no options, parse user
//                 //     state.next();
//                 //     skip_iter = true;
//                 // }
//                 _ => {
//                     state.next();
//                     skip_iter = true;
//                 }
//             },
//             ParseState::User => {
//                 match str.as_str() {
//                     "cmd" => {
//                         str.clear();
//                         state.next();
//                         continue;
//                     }
//                     "as" => {
//                         if config.user.is_some() || config.group.is_some() {
//                             parsing_target = true;
//                             str.clear();
//                             continue;
//                         } else {
//                             return Err(ConfigError::Format("missing identity before as".into()));
//                         }
//                     }
//                     _ if parsing_target => {
//                         parsing_target = false;
//                         config.target = Some(str.to_string());
//                         str.clear();
//                         continue;
//                     }
//                     _ => {
//                         if config.user.is_some() || config.group.is_some() {
//                             break;
//                         }
//                     }
//                 }
//                 match str.split_once(":") {
//                     Some((user, group)) => {
//                         if !user.is_empty() {
//                             config.user = Some(user.to_string());
//                         }
//                         if !group.is_empty() {
//                             config.group = Some(group.to_string());
//                         }
//                     }
//                     None => {
//                         config.user = Some(str.to_string());
//                     }
//                 }
//                 str.clear();
//             }
//             ParseState::Cmd => {
//                 if config.cmd.is_none() {
//                     config.cmd = Some(str.to_string());
//                     str.clear();
//                 } else if str == "args" {
//                     str.clear();
//                     state.next();
//                 } else {
//                     break;
//                 }
//             }
//             ParseState::CmdArgs => {
//                 let args = config.cmd_args.get_or_insert(Vec::new());
//                 args.push(str.to_string());
//                 str.clear();
//             }
//         }
//     }

//     Ok(config)
// }

struct Tokenizer<'a> {
    chars: Peekable<Chars<'a>>,
    line: usize,
    str: String,
    skipping_comment: bool,
    line_has_content: bool,
    line_finished: bool,
    finished: bool,
    peeked: Option<String>,
}

impl<'a> Tokenizer<'a> {
    fn new(chars: Peekable<Chars<'a>>) -> Self {
        Self {
            chars,
            line: 1,
            str: String::new(),
            skipping_comment: false,
            line_has_content: false,
            line_finished: false,
            finished: false,
            peeked: None,
        }
    }

    fn line(&self) -> usize {
        self.line
    }

    fn next_line(&mut self) -> bool {
        if self.finished {
            return false;
        }
        if self.line_finished {
            self.line += 1;
            self.line_finished = false;
        }
        if self.chars.peek().is_none() {
            self.finished = true;
        }
        !self.finished
    }
    fn peek(&mut self) -> Option<&String> {
        if let Some(ref peeked) = self.peeked {
            return Some(peeked);
        } else {
            match self.next() {
                Some(s) => {
                    self.peeked = Some(s);
                    return Some(self.peeked.as_ref().unwrap());
                }
                None => {
                    return None;
                }
            }
        }
    }
    fn collect(&mut self) -> Vec<String> {
        let mut list = Vec::new();
        while let Some(s) = self.next() {
            list.push(s);
        }
        list
    }

    fn next(&mut self) -> Option<String> {
        if self.peeked.is_some() {
            return std::mem::take(&mut self.peeked);
        }
        if self.line_finished || self.finished {
            return None;
        }
        while let Some(ch) = self.chars.next() {
            if self.skipping_comment {
                if ch != '\n' {
                    continue;
                } else {
                    self.skipping_comment = false;
                    if !self.str.is_empty() {
                        self.line_finished = true;
                        return Some(std::mem::take(&mut self.str));
                    } else if self.line_has_content {
                        self.line_finished = true;
                        self.line_has_content = false;
                        return None;
                    } else {
                        self.line += 1;
                        continue;
                    }
                }
            }
            match ch {
                ' ' => {
                    if !self.str.is_empty() {
                        return Some(std::mem::take(&mut self.str));
                    }
                    continue;
                }
                '\n' => {
                    if !self.str.is_empty() {
                        self.line_finished = true;
                        return Some(std::mem::take(&mut self.str));
                    } else if self.line_has_content {
                        self.line_finished = true;
                        self.line_has_content = false;
                        return None;
                    } else {
                        self.line += 1;
                        continue;
                    }
                }
                // skip comment
                '#' => {
                    self.skipping_comment = true;
                    continue;
                }
                _ => {
                    if !self.line_has_content {
                        self.line_has_content = true;
                    }
                    self.str.push(ch);
                }
            }
        }
        self.finished = true;
        None
    }
}

// fn tokenizer(content: &str) -> Result<Vec<Vec<String>>, ConfigError<'_>> {
//     let mut str = String::new();
//     let mut tokens = Vec::new();
//     let mut lines = Vec::new();
//     let mut skipping_comment = false;
//     let mut line_count = 0;
//     for ch in content.chars() {
//         if skipping_comment {
//             if ch != '\n' {
//                 continue;
//             } else {
//                 skipping_comment = false;
//                 line_count += 1;
//             }
//         }
//         match ch {
//             ' ' => {
//                 if !str.is_empty() {
//                     tokens.push(std::mem::take(&mut str));
//                 }
//                 continue;
//             }
//             '\n' => {
//                 line_count += 1;
//                 if !str.is_empty() {
//                     tokens.push(std::mem::take(&mut str));
//                 }
//                 if !tokens.is_empty() {
//                     lines.push(std::mem::take(&mut tokens));
//                 }
//             }
//             // skip comment
//             '#' => {
//                 if !str.is_empty() {
//                     tokens.push(std::mem::take(&mut str));
//                 }
//                 if !tokens.is_empty() {
//                     lines.push(std::mem::take(&mut tokens));
//                 }
//                 skipping_comment = true;
//             }
//             _ => {
//                 str.push(ch);
//             }
//         }
//     }
//     Ok(lines)
// }

fn parser<'a>(tokens: &mut Tokenizer<'_>) -> Result<Config, ConfigError<'a>> {
    // let mut tokens = tokens.into_iter().peekable();

    // there must be an action
    let action = match tokens.next() {
        Some(s) if s == "permit" => Action::Permit,
        Some(s) if s == "deny" => Action::Deny,
        _ => return Err(ConfigError::Syntax("missing action".into(), tokens.line())),
    };

    // optional options
    let mut options = Options::default();
    'outer: loop {
        match tokens.peek() {
            Some(token) => match token.as_str() {
                "nopass" => {
                    options.nopass = true;
                    tokens.next();
                }
                "nolog" => {
                    options.nolog = true;
                    tokens.next();
                }
                "persist" => {
                    options.persist = true;
                    tokens.next();
                }
                "keepenv" => {
                    options.keepenv = true;
                    tokens.next();
                }
                "setenv" => {
                    tokens.next();
                    if !tokens.next().is_some_and(|s| s == "{") {
                        return Err(ConfigError::Syntax(
                            "missing envs after \"setenv\"".into(),
                            tokens.line(),
                        ));
                    }
                    while let Some(token) = tokens.next() {
                        if token == "}" {
                            if options.envs.is_empty() {
                                return Err(ConfigError::Syntax(
                                    "missing envs inside \"{}\"".into(),
                                    tokens.line(),
                                ));
                            }
                            continue 'outer;
                        } else if let Some((nothing, env)) = token.split_once("-")
                            && nothing.is_empty()
                        {
                            if env.is_empty() {
                                return Err(ConfigError::Syntax(
                                    format!("invalid env: {token}, missing an env after \"-\"")
                                        .into(),
                                    tokens.line(),
                                ));
                            }
                            options.envs.push(Env::Remove(env.to_string()));
                        } else if let Some((key, val)) = token.split_once("=") {
                            if key.is_empty() {
                                return Err(ConfigError::Syntax(
                                    format!("invalid env: {token}, missing a key before \"=\"")
                                        .into(),
                                    tokens.line(),
                                ));
                            }
                            if val.is_empty() {
                                return Err(ConfigError::Syntax(
                                    format!("invalid env: {token}, missing a value after \"=\"")
                                        .into(),
                                    tokens.line(),
                                ));
                            }
                            let val = match val.split_once("$") {
                                Some((nothing, value)) => {
                                    if !nothing.is_empty() || value.is_empty() {
                                        return Err(ConfigError::Syntax(
                                            format!("invalid env value: {}", val).into(),
                                            tokens.line(),
                                        ));
                                    }
                                    Val::FromEnv(value.to_string())
                                }
                                None => Val::New(val.to_string()),
                            };
                            options.envs.push(Env::Set {
                                key: key.to_string(),
                                val,
                            });
                        } else {
                            options.envs.push(Env::Keep(token));
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
            None => {
                return Err(ConfigError::Syntax(
                    "missing identity".into(),
                    tokens.line(),
                ));
            }
        }
    }

    // there must be an identity
    let Some(identity) = tokens.next() else {
        return Err(ConfigError::Syntax(
            "missing identity".into(),
            tokens.line(),
        ));
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
        && token == "as"
    {
        tokens.next();
        // parse target
        match tokens.next() {
            Some(target) => Some(target),
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
        if token != "cmd" {
            return Err(ConfigError::Syntax(
                "expected \"cmd\" before command".into(),
                tokens.line(),
            ));
        }
        let Some(cmd) = tokens.next() else {
            return Err(ConfigError::Syntax(
                "missing command after \"cmd\"".into(),
                tokens.line(),
            ));
        };
        // optional args
        let cmd_args = match tokens.peek() {
            Some(_) => Some(tokens.collect()),
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
    match Config::parse("tests/doas.conf", false) {
        Ok(rules) => println!("{:#?}", rules),
        Err(e) => eprintln!("{e}"),
    }
}

fn check_uid(uid: uid_t, desired: &str) -> Result<(), ()> {
    let desired = c::parse_uid(desired)?;
    if desired == uid { Ok(()) } else { Err(()) }
}

// fn strcmp<C, S>(c_str: C, str: S) -> Result<(), ()>
// where
//     C: AsRef<CStr>,
//     S: AsRef<str>,
// {
//     if c_str.as_ref().to_bytes() == str.as_ref().as_bytes() {
//         Ok(())
//     } else {
//         Err(())
//     }
// }

impl Config {
    pub fn parse(path: &str, check_perm: bool) -> Result<Vec<Config>, ConfigError<'_>> {
        let mut file = fs::File::open(path).map_err(|e| ConfigError::IO(e, path))?;
        if check_perm {
            // check file permission
            let meta = file.metadata().map_err(|e| ConfigError::IO(e, path))?;
            // don't forget to mask out file type bits
            // Lower 9 bits are rwx permissions; higher bits encode file type
            if (meta.permissions().mode() & 0o777) != 0o644 {
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
        let mut tokenizer = Tokenizer::new(content.chars().peekable());
        while tokenizer.next_line() {
            let rule = parser(&mut tokenizer)?;
            rules.push(rule);
        }
        // let token_rules = tokenizer(&content)?;
        // println!("{:?}", token_rules);
        // for tokens in token_rules {
        //     let rule = parser(tokens)?;
        //     rules.push(rule);
        // }
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
pub fn permit<'a>(
    rules: &'a [Config],
    uid: uid_t,
    groups: &[gid_t],
    target: uid_t,
    cmd: &OsStr,
    cmd_args: &[OsString],
) -> Option<&'a Config> {
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
        println!("the configuration file {path} syntax is ok");
        return Ok(());
    }
    if let Some(r) = permit(&rules, uid, groups, target, &cmds[0], &cmds[1..]) {
        println!("permit, nopass: {}", r.options.nopass);
        Ok(())
    } else {
        println!("deny");
        Err(())
    }
}
