use std::{
    ffi::{CStr, CString, OsString},
    marker::PhantomData,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

use crate::utils::{array::Array, fmt::Part};

pub struct CArgs<'b, const PARTS: usize, const ARGS: usize> {
    pub parts: Array<PARTS, Part<'static>>,
    pub args: [FmtWriter<'b>; ARGS],
    pub count: usize,
}

type WriteFn = unsafe fn(data: *const (), len: usize, buf: &mut Vec<u8>);

pub struct FmtWriter<'a> {
    data: *const (),
    len: usize,
    write: WriteFn,
    _life: PhantomData<&'a ()>,
}

impl<'a> FmtWriter<'a> {
    unsafe fn new(data: *const (), len: usize, write: WriteFn, _life: &'a ()) -> Self {
        Self {
            data,
            len,
            write,
            _life: PhantomData,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn write(&self, buf: &mut Vec<u8>) {
        unsafe {
            (self.write)(self.data, self.len, buf);
        }
    }
}

unsafe fn general_write(data: *const (), len: usize, buf: &mut Vec<u8>) {
    unsafe {
        let data = data as *const u8;
        let slice = core::slice::from_raw_parts(data, len);
        buf.extend(slice);
    }
}

pub trait WriteToBytes<'a> {
    fn get_writer(&'a self) -> FmtWriter<'a>;
}

impl<'a> WriteToBytes<'a> for usize {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let s = self.to_string();
        let bytes = s.as_bytes();
        let data = bytes.as_ptr() as *const ();
        unsafe { FmtWriter::new(data, bytes.len(), general_write, &()) }
    }
}

impl<'a> WriteToBytes<'a> for CStr {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let data = self.as_ptr() as *const ();
        unsafe { FmtWriter::new(data, self.count_bytes(), general_write, &()) }
    }
}

impl<'a> WriteToBytes<'a> for CString {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let data = self.as_ptr() as *const ();
        unsafe { FmtWriter::new(data, self.count_bytes(), general_write, &()) }
    }
}

impl<'a> WriteToBytes<'a> for OsString {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let bytes = self.as_bytes();
        let data = bytes.as_ptr() as *const ();
        unsafe { FmtWriter::new(data, bytes.len(), general_write, &()) }
    }
}

impl<'a> WriteToBytes<'a> for PathBuf {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let bytes = self.as_os_str().as_bytes();
        let data = bytes.as_ptr() as *const ();
        unsafe { FmtWriter::new(data, bytes.len(), general_write, &()) }
    }
}

impl<'a, const N: usize, const S: usize> WriteToBytes<'a> for CArgs<'a, N, S> {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        unsafe fn write<const N: usize, const S: usize>(
            data: *const (),
            _len: usize,
            buf: &mut Vec<u8>,
        ) {
            let me = unsafe {
                let data = data as *const CArgs<'_, N, S>;
                &*data
            };
            let mut args = me.args.iter();
            for part in me.parts.as_slice() {
                match part {
                    Part::Arg => {
                        let writer = args
                            .next()
                            .expect("we have checked args == ARG_COUNT at compile time");
                        writer.write(buf);
                    }
                    Part::Text(str) => {
                        buf.extend(str.as_bytes());
                    }
                }
            }
        }
        let data = self as *const _ as *const ();
        unsafe { FmtWriter::new(data, self.count, write::<N, S>, &()) }
    }
}

pub trait WriteStrToBytes<'a> {
    fn get_writer(&'a self) -> FmtWriter<'a>;
}

impl<'a, T> WriteStrToBytes<'a> for T
where
    T: AsRef<str>,
{
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let str = self.as_ref();
        let data = str.as_ptr() as *const ();
        unsafe { FmtWriter::new(data, str.len(), general_write, &()) }
    }
}
