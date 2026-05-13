use std::{
    borrow::Cow,
    ffi::{CStr, CString, OsString},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

pub trait StrToBytes {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]>;
}

impl<T> StrToBytes for T
where
    T: AsRef<str>,
{
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.as_ref().as_bytes().into()
    }
}

pub trait SpecificToBytes {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]>;
}

impl SpecificToBytes for &CStr {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.to_bytes().into()
    }
}

impl SpecificToBytes for CString {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.to_bytes().into()
    }
}

impl SpecificToBytes for OsString {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.as_bytes().into()
    }
}

impl SpecificToBytes for PathBuf {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.as_os_str().as_bytes().into()
    }
}
