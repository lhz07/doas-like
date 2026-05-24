use crate::utils::{array::ArrayRef, fmt::Part};
use std::{
    ffi::{CStr, CString, OsString},
    fmt::Display,
    io::Write as _,
    marker::PhantomData,
    os::unix::ffi::OsStrExt as _,
    path::PathBuf,
    ptr::NonNull,
};

pub struct CArgs<'a, const ARGS: usize> {
    pub parts: &'static ArrayRef<Part<'static>>,
    pub args: [FmtWriter<'a>; ARGS],
    pub count: usize,
}

type WriteFn = unsafe fn(data: NonNull<()>, len: usize, buf: &mut Vec<u8>);

pub struct FmtWriter<'a> {
    data: NonNull<()>,
    len: usize,
    write: WriteFn,
    _life: PhantomData<&'a ()>,
}

impl<'a> FmtWriter<'a> {
    fn new_bytes(bytes: &'a [u8]) -> Self {
        unsafe fn general_write(data: NonNull<()>, len: usize, buf: &mut Vec<u8>) {
            unsafe {
                let data: NonNull<u8> = data.cast();
                let slice = core::slice::from_raw_parts(data.as_ptr(), len);
                buf.extend(slice);
            }
        }
        let data = NonNull::from_ref(bytes).cast();
        Self {
            data,
            len: bytes.len(),
            write: general_write,
            _life: PhantomData,
        }
    }

    unsafe fn new_ref<T>(x: &'a T, len: usize, write: WriteFn) -> Self {
        let data = NonNull::from_ref(x).cast();
        Self {
            data,
            len,
            write,
            _life: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn write(&self, buf: &mut Vec<u8>) {
        unsafe {
            (self.write)(self.data, self.len, buf);
        }
    }
}

pub trait WriteToBytes<'a> {
    fn get_writer(&'a self) -> FmtWriter<'a>;
}

impl<'a> WriteToBytes<'a> for CStr {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let bytes = self.to_bytes();
        FmtWriter::new_bytes(bytes)
    }
}

impl<'a> WriteToBytes<'a> for CString {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let bytes = self.to_bytes();
        FmtWriter::new_bytes(bytes)
    }
}

impl<'a> WriteToBytes<'a> for OsString {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let bytes = self.as_bytes();
        FmtWriter::new_bytes(bytes)
    }
}

impl<'a> WriteToBytes<'a> for PathBuf {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        let bytes = self.as_os_str().as_bytes();
        FmtWriter::new_bytes(bytes)
    }
}

impl<'a> WriteToBytes<'a> for [u8] {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        FmtWriter::new_bytes(self)
    }
}

impl<'a, const N: usize> WriteToBytes<'a> for CArgs<'a, N> {
    fn get_writer(&'a self) -> FmtWriter<'a> {
        unsafe fn write<const N: usize>(data: NonNull<()>, _len: usize, buf: &mut Vec<u8>) {
            let me: &CArgs<'_, N> = unsafe { data.cast().as_ref() };
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

        unsafe { FmtWriter::new_ref(self, self.count, write::<N>) }
    }
}

pub trait WriteStrToBytes<'a> {
    fn get_writer(&'a self) -> FmtWriter<'a>;
}

impl<'a, T> WriteStrToBytes<'a> for T
where
    T: Display,
{
    fn get_writer(&'a self) -> FmtWriter<'a> {
        unsafe fn display_write<T: Display>(ptr: NonNull<()>, _len: usize, buf: &mut Vec<u8>) {
            let r = unsafe { ptr.cast::<T>().as_ref() };
            let _ = write!(buf, "{}", r);
        }

        unsafe { FmtWriter::new_ref(self, 1, display_write::<T>) }
    }
}
