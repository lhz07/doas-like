#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unnecessary_transmutes)]
#![allow(nonstandard_style)]

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(crate) use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::*;
