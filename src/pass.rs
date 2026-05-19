use crate::{c, utils::array::ArrayRef};
use std::{
    ffi::{CStr, c_char},
    fs,
    io::{self, Read as _, Write as _},
    os::fd::AsFd as _,
};

pub fn read_passwd(prompt: &CStr, buf: &mut ArrayRef<c_char>, pwfeedback: bool) -> io::Result<()> {
    let mut term = Term::new(buf, pwfeedback)?;
    term.write(prompt.to_bytes())?;
    loop {
        match term.read()? {
            b'\n' | b'\r' | CTRL_D => {
                break;
            }
            CTRL_C => {
                drop(term);
                std::process::exit(1);
            }
            CTRL_U if !term.buf.is_empty() => {
                if term.pwfeedback {
                    term.write(&CLEAR.repeat(term.buf.len()))?;
                }
                term.buf.clear();
            }

            BACKSPACE | DEL if !term.buf.is_empty() => {
                if pwfeedback {
                    term.write(CLEAR)?;
                }
                term.buf.pop();
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
const CLEAR: &[u8; 3] = b"\x08 \x08";
const CTRL_D: u8 = b'\x04';
const CTRL_U: u8 = b'\x15';

fn open_tty() -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
}

struct Term<'a> {
    tty: fs::File,
    origin_termios: libc::termios,
    buf: &'a mut ArrayRef<c_char>,
    pwfeedback: bool,
}

impl<'a> Term<'a> {
    fn new(buf: &'a mut ArrayRef<c_char>, pwfeedback: bool) -> io::Result<Self> {
        let tty = open_tty()?;
        let origin_termios = c::get_terminal_attr(tty.as_fd())?;
        let mut termios = origin_termios;
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

impl<'a> Drop for Term<'a> {
    fn drop(&mut self) {
        if self.pwfeedback && !self.buf.is_empty() {
            // clear the feedback
            let _ = self.write(&CLEAR.repeat(self.buf.len()));
        }
        let _ = self.write(b"\r\n");
        let _ = c::set_terminal_attr(self.tty.as_fd(), &self.origin_termios);
    }
}
