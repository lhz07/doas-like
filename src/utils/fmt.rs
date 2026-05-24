use crate::utils::array::{self, Array};

#[derive(Debug)]
pub enum Part<'a> {
    /// Placeholder for a formatting argument.
    Arg,
    /// Literal text segment.
    Text(&'a str),
}

/// Preprocesses the format string.
///
/// Replaces each `{}` placeholder with `0` as an internal separator,
/// while handling escaped braces (`{{` and `}}`).
///
/// The resulting byte array is later consumed by `format_str`.
pub const fn prep_str<const N: usize>(bytes: &[u8], args: usize) -> Array<N, u8> {
    assert!(N == bytes.len());
    let mut out = Array::<N, u8>::new();
    let mut i = 0;
    let mut in_brace = false;
    let mut arg_count = 0;
    while i < N {
        let ch = bytes[i];
        match ch {
            b'{' => {
                if in_brace {
                    // escape {
                    in_brace = false;
                    out.push(ch);
                } else {
                    in_brace = true;
                }
            }
            b'}' => {
                if !in_brace {
                    if i + 1 < N && bytes[i + 1] == b'}' {
                        // excape }
                        out.push(ch);
                        i += 1;
                    } else {
                        panic!("mismatch '}}'");
                    }
                } else {
                    // finish a placeholder
                    in_brace = false;
                    arg_count += 1;
                    out.push(0);
                }
            }
            0 => {
                panic!("nul character is not allowed here");
            }
            _ => {
                assert!(!in_brace, "mismatch '{{'");
                out.push(ch);
            }
        }

        i += 1;
    }

    assert!(!in_brace, "mismatch '{{'");

    assert!(args == arg_count, "mismatch args");

    out
}

/// Splits the preprocessed byte slice into formatting parts.
///
/// `0` bytes are interpreted as argument placeholders.
pub const fn format_str<'a, const PARTS: usize>(bytes: &'a [u8]) -> Array<PARTS, Part<'a>> {
    let mut parts = Array::<PARTS, _>::new();
    let mut i = 0;
    let mut text_i = None;
    let len = bytes.len();
    while i < len {
        let ch = bytes[i];
        match ch {
            0 => {
                // Flush pending text segment.
                if let Some(start) = text_i.take() {
                    let s = array::slice(bytes, start..i);
                    let Ok(s) = str::from_utf8(s) else {
                        panic!("invalid str");
                    };
                    parts.push(Part::Text(s));
                }

                parts.push(Part::Arg);
            }
            _ => {
                if text_i.is_none() {
                    text_i = Some(i);
                }
            }
        }

        i += 1;
    }

    // Flush trailing text segment.
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
macro_rules! c_format{
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::utils::convert::WriteStrToBytes;
        #[allow(unused_imports)]
        use $crate::utils::convert::WriteToBytes;
        use $crate::utils::convert::FmtWriter;
        use $crate::utils::fmt::*;
        use $crate::utils::array::Array;
        use std::ffi::CString;

        const ARG_COUNT: usize = $crate::count_args!($($arg,)*);
        // Maximum possible number of parts:
        // text + arg + text + ...
        const MAX_PARTS: usize = ARG_COUNT * 2 + 1;
        const N: usize = $fmt.len();
        const BYTES: Array<N, u8> = prep_str::<N>($fmt.as_bytes(), ARG_COUNT);
        // Final static byte count excluding placeholders,
        // plus the trailing nul byte.
        const BYTES_LEN: usize = BYTES.len() + 1 - ARG_COUNT;
        const PARTS: Array<MAX_PARTS, Part<'_>> = format_str::<MAX_PARTS>(BYTES.as_slice());
        #[allow(unused_mut)]
        let mut count = BYTES_LEN;
        let arrays: [FmtWriter<'_>; _] = [ $( {
            let writer = $arg.get_writer();
            count += writer.len();
            writer
        }),* ];
        let mut args = arrays.iter();
        let mut buf = Vec::with_capacity(count);
        for part in PARTS.as_slice(){
            match part{
                Part::Arg => {
                    let writer = args.next().expect("we have checked args == ARG_COUNT at compile time");
                    writer.write(&mut buf);
                }
                Part::Text(str) => {
                    buf.extend(str.as_bytes());
                }
            }
        }
        // Replace nul bytes with spaces to keep CString valid.
        for byte in buf.iter_mut(){
            if *byte == 0{
                *byte = 32;
            }
        }
        buf.push(0);
        // Safety: we have replaced all nul bytes and pushed a `0` at the end.
        #[allow(unused_unsafe)]
        unsafe { CString::from_vec_with_nul_unchecked(buf) }
    }};
}

#[macro_export]
macro_rules! c_format_args{
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::utils::convert::*;
        use $crate::utils::fmt::*;
        use $crate::utils::array::Array;

        const ARG_COUNT: usize = $crate::count_args!($($arg,)*);
        // Maximum possible number of parts:
        // text + arg + text + ...
        const MAX_PARTS: usize = ARG_COUNT * 2 + 1;
        const N: usize = $fmt.len();
        const BYTES: Array<N, u8> = prep_str::<N>($fmt.as_bytes(), ARG_COUNT);
        // Final static byte count excluding placeholders
        const BYTES_LEN: usize = BYTES.len() - ARG_COUNT;
        const PARTS: Array<MAX_PARTS, Part<'_>> = format_str::<MAX_PARTS>(BYTES.as_slice());
        #[allow(unused_mut)]
        let mut count = BYTES_LEN;
        let arrays: [FmtWriter<'_>; _] = [ $( {
            let writer = $arg.get_writer();
            count += writer.len();
            writer
        }),* ];

        CArgs{
            parts: PARTS.as_array_ref(),
            args: arrays,
            count,
        }
    }};
}

#[test]
fn prepare_str() {
    let parts = const {
        const STR: &str = "{{hello}}, {}!!!";
        const N: usize = STR.len();
        prep_str::<N>(STR.as_bytes(), 1)
    };
    assert_eq!(b"{hello}, \0!!!", parts.as_slice());
}

#[test]
fn format_macro() {
    let cstr = c_format!("{{hello}}, {} {}", "world", c"and cstr");
    assert_eq!(c"{hello}, world and cstr", &cstr);
    let cstr = c_format!("{} {}", "hello", c"world");
    assert_eq!(c"hello world", &cstr);
    let cstr = c_format!("hello, world");
    assert_eq!(c"hello, world", &cstr);
}

#[test]
fn format_args() {
    let c = std::ffi::CString::from(c"world");
    let a = c_format_args!("hello, {}", c);
    let cstr = c_format!("doas: {}", a);
    assert_eq!(c"doas: hello, world", &cstr);
}

#[test]
fn format_display_args() {
    let c = "world".to_string();
    let a = c_format_args!("hello, {}", c);
    let cstr = c_format!("doas: {}, {}", a, 123);
    assert_eq!(c"doas: hello, world, 123", &cstr);
}
