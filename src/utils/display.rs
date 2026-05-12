use crate::utils::array::{self, Array};

#[derive(Debug)]
pub enum Part<'a> {
    Arg,
    Text(&'a str),
}

pub const fn format_str<'a, const N: usize, const PARTS: usize, const ARGS: usize>(
    bytes: &'a [u8],
) -> Array<PARTS, Part<'a>> {
    assert!(N == bytes.len());
    let mut parts = Array::<PARTS, _>::new();
    let mut i = 0;
    let mut text_i = None;
    let mut in_brace = false;
    let mut arg_count = 0;
    while i < N {
        let ch = bytes[i];
        match ch {
            b'{' => {
                if in_brace {
                    // escape {
                    in_brace = false;
                    if text_i.is_none() {
                        text_i = Some(i - 1);
                    }
                } else {
                    if let Some(start) = text_i.take() {
                        let s = array::slice(bytes, start..i);
                        let Ok(s) = str::from_utf8(s) else {
                            panic!("invalid str");
                        };
                        parts.push(Part::Text(s));
                    }
                    in_brace = true;
                }
            }
            b'}' => {
                if !in_brace {
                    if i + 1 < N && bytes[i + 1] == b'}' {
                        // excape }
                        if text_i.is_none() {
                            text_i = Some(i);
                        }
                        i += 1;
                    } else {
                        panic!("mismatch '}}'");
                    }
                } else {
                    // finish an arg
                    in_brace = false;
                    arg_count += 1;
                    parts.push(Part::Arg);
                }
            }
            _ => {
                if in_brace {
                    panic!("mismatch '{{'");
                }
                if text_i.is_none() {
                    text_i = Some(i);
                }
            }
        }

        i += 1;
    }

    assert!(ARGS == arg_count, "mismatch args");

    if let Some(start) = text_i.take() {
        let s = array::slice(bytes, start..i);
        let Ok(s) = str::from_utf8(s) else {
            panic!("invalid str");
        };
        parts.push(Part::Text(s));
    }

    parts
}

#[macro_export]
macro_rules! count_args {
    ($($arg:expr),* $(,)?) => {
        <[()]>::len(&[$($crate::count_args!(@sub $arg)),*])
    };
    (@sub $_arg:expr) => { () };
}

#[macro_export]
macro_rules! format_c {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::display::ToBytes;
        #[allow(unused_imports)]
        use $crate::display::SpecificToBytes;
        use $crate::utils::display::*;
        use $crate::utils::array::Array;
        use std::ffi::CString;
        use std::borrow::Cow;
        const ARG_COUNT: usize = $crate::count_args!($($arg,)*);
        const MAX_PARTS: usize = ARG_COUNT * 2 + 1;
        const N: usize = $fmt.len();
        const PARTS: Array<MAX_PARTS, Part<'_>> = format_str::<N, MAX_PARTS, ARG_COUNT>($fmt.as_bytes());
        #[allow(unused_mut)]
        let mut count = 0;
        let arrays: [Cow<'_, [u8]>; _] = [ $( { let a = $arg.to_raw_bytes(); count += a.len(); a }),* ];
        let mut args = arrays.iter();
        let mut buf = Vec::with_capacity(count);
        for part in PARTS.as_slice(){
            match part{
                Part::Arg => {
                    let bytes = args.next().expect("args should be equal to ARG_COUNT") ;
                    buf.extend(bytes.as_ref());
                }
                Part::Text(str) => {
                    buf.extend(str.as_bytes());
                }
            }
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
fn format_literal() {
    let parts = const {
        const STR: &str = "{{hello}}, {}!!!";
        const N: usize = STR.len();
        format_str::<N, 3, 1>(STR.as_bytes())
    };
    println!("{:?}", parts.as_slice());
}

#[test]
fn format_macro() {
    let cstr = format_c!("hello, {} {}", "world", c"and cstr");
    assert_eq!(c"hello, world and cstr", &cstr);
    let cstr = format_c!("{} {}", "hello", c"world");
    assert_eq!(c"hello world", &cstr);
    let cstr = format_c!("hello, world");
    assert_eq!(c"hello world", &cstr);
}
