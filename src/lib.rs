#![cfg_attr(feature = "nightly", feature(gen_blocks))]

use std::ffi::CStr;

pub mod bindings;
pub mod c;
pub mod command;
pub mod config;
pub mod insults;
pub mod pam;
pub mod pass;
pub mod sys;
pub mod timestamp;
pub mod tokenizer;
pub mod utils;
pub mod verify;

pub const CNAME: &CStr = c"doas";
pub const NAME: &str = "doas";
pub const CONF_PATH: &str = "/etc/doas.conf";
pub const SAFE_PATH: &str = "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin";

#[macro_export]
macro_rules! warnx {
    ($($arg:tt)*) => {{
        eprintln!("{}: {}", $crate::NAME, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        let args = $crate::c_format_args!($($arg)*);
        let s = $crate::c_format!("{}: {}", $crate::NAME, args);
        $crate::c::perror(&s);
    }};
}

#[macro_export]
macro_rules! eprintf {
    ($($arg:tt)*) => {{
        let s = $crate::c_format!($($arg)*);
        $crate::c::eprint(s.to_bytes());
    }};
}

#[macro_export]
macro_rules! errx {
    ($($arg:tt)*) => {{
        $crate::warnx!($($arg)*);
        return Err(());
    }};
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {{
        $crate::warn!($($arg)*);
        return Err(());
    }};
}

#[macro_export]
macro_rules! err_exit {
    ($($arg:tt)*) => {{
        $crate::warn!($($arg)*);
        std::process::exit(1);
    }};
}
