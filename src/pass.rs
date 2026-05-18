use crate::{c, utils::array::Array};
use std::{
    ffi::{CStr, c_char},
    fs,
    io::{self, Read, Write},
    os::fd::AsFd,
};

pub fn read_passwd<const N: usize>(
    prompt: &CStr,
    buf: &mut Array<N, c_char>,
    pwfeedback: bool,
) -> io::Result<()> {
    let mut term = Term::new(buf, pwfeedback)?;
    term.write(prompt.to_bytes())?;
    loop {
        match term.read()? {
            b'\n' | b'\r' => {
                break;
            }
            CTRL_C => {
                drop(term);
                std::process::exit(1);
            }
            BACKSPACE | DEL => {
                if !term.buf.is_empty() {
                    if pwfeedback {
                        term.write(b"\x08 \x08")?;
                    }
                    term.buf.pop();
                }
            }
            ch if !ch.is_ascii_control() => {
                term.buf
                    .push_checked(ch as c_char)
                    .map_err(|_| io::Error::other("too long password"))?;
                if pwfeedback {
                    term.write(b"*")?;
                }
            }
            _ => {}
        }
    }
    term.buf
        .push_checked(0)
        .map_err(|_| io::Error::other("too long password"))?;
    Ok(())
}

const BACKSPACE: u8 = b'\x08';
const DEL: u8 = b'\x7F';
const CTRL_C: u8 = b'\x03';
// TODO: support these
// const CTRL_D: u8 = b'\x04';
// const CTRL_U: u8 = b'\x15';
// const CTRL_W: u8 = b'\x17';

fn open_tty() -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
}

struct Term<'a, const N: usize> {
    tty: fs::File,
    origin_termios: libc::termios,
    buf: &'a mut Array<N, c_char>,
    pwfeedback: bool,
}

impl<'a, const N: usize> Term<'a, N> {
    fn new(buf: &'a mut Array<N, c_char>, pwfeedback: bool) -> io::Result<Self> {
        let tty = open_tty()?;
        let mut termios = c::get_terminal_attr(tty.as_fd())?;
        let origin_termios = termios.clone();
        c::cfmakeraw(&mut termios);
        // termios.c_lflag &= !(libc::ECHO | libc::ICANON);
        c::set_terminal_attr(tty.as_fd(), &termios)?;
        let term = Self {
            buf,
            tty,
            origin_termios,
            pwfeedback,
        };
        Ok(term)
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.tty.write_all(buf)?;
        Ok(())
    }

    fn read(&mut self) -> io::Result<u8> {
        let mut buf = [0; 1];
        self.tty.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl<'a, const N: usize> Drop for Term<'a, N> {
    fn drop(&mut self) {
        if self.pwfeedback && self.buf.len() > 0 {
            // clear the feedback
            if self.buf.len() > 1 {
                let _ = self.write(format!("\x1b[{}D", self.buf.len() - 1).as_bytes());
            }
            let _ = self.write(b"\x1b[K");
        }
        let _ = self.write(b"\r\n");
        let _ = c::set_terminal_attr(self.tty.as_fd(), &self.origin_termios);
    }
}
