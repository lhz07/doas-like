#![allow(clippy::result_unit_err)]
#![cfg_attr(feature = "nightly", feature(gen_blocks))]

#[global_allocator]
static GLOBAL: System = System;

use std::{alloc::System, ffi::CStr};

pub mod bindings;
pub mod c;
pub mod command;
pub mod config;
pub mod insults;
pub mod pam;
pub mod timestamp;
pub mod tokenizer;
pub mod utils;
pub mod verify;

pub const CNAME: &CStr = c"doas";
pub const NAME: &str = "doas";
pub const CONF_PATH: &str = "/etc/doas.conf";

#[macro_export]
macro_rules! errx {
    ($($arg:tt)*) => {{
        eprintln!("{}: {}", $crate::NAME, format_args!($($arg)*));
        return Err(());
    }};
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {{
        eprint!("{}: {}: ", $crate::NAME, format_args!($($arg)*));
        $crate::c::perror(c"");
        return Err(());
    }};
}

#[macro_export]
macro_rules! errprint {
    ($($arg:tt)*) => {{
        eprintln!("{}: {}", $crate::NAME, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        eprintln!("{} warning: {}", $crate::NAME, format_args!($($arg)*));
    }};
}
