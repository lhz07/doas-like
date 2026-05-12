use std::{
    borrow::Cow,
    ffi::{CStr, CString},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

pub trait ToBytes<T> {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]>;
}

impl<T> ToBytes<T> for T
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

impl SpecificToBytes for PathBuf {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.as_os_str().as_bytes().into()
    }
}

impl SpecificToBytes for Vec<u8> {
    fn to_raw_bytes<'a>(&'a self) -> Cow<'a, [u8]> {
        self.as_slice().into()
    }
}

#[macro_export]
macro_rules! cat_cstr {
    ($($arg:expr),* $(,)?) => {{
        use $crate::display::ToBytes;
        use std::ffi::CString;
        let mut count = 0;
        let arrays = [ $( { let a = $arg.to_raw_bytes(); count += a.len(); a }),* ];
        let mut buf = Vec::with_capacity(count);
        for bytes in arrays{
            buf.extend(bytes.as_ref());
        }
        for byte in buf.iter_mut(){
            if *byte == 0{
                *byte = 32;
            }
        }
        buf.push(0);
        unsafe { CString::from_vec_with_nul_unchecked(buf) }
    }};
}

#[test]
fn display_cstr() {
    let s = cat_cstr!("hello", "wor\0ld", c"hhh");
    unsafe {
        libc::printf(c"%s\n".as_ptr(), s.as_ptr());
    }
}
