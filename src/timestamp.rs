use crate::bindings::timespec;
use crate::{c, err, errx, warnx};
use std::time::Duration;
use std::{
    cmp,
    fs::{self, File, FileTimes, Permissions},
    io, ops,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::SystemTime,
};

const TIMESTAMP_DIR: &str = "/var/run/doas";

fn get_path() -> Result<PathBuf, ()> {
    let proc = c::get_proc_info()?;
    // 2-2-34816-470-0
    Ok(Path::new(TIMESTAMP_DIR).join(format!(
        "{}-{}-{}-{}-{}",
        proc.ppid,
        proc.sid,
        proc.tty,
        proc.start_time,
        c::getuid()
    )))
}

pub fn clear() -> Result<(), ()> {
    let path = get_path()?;
    if let Err(e) = fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        err!("can not remove timestamp file");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Time(timespec);

impl ops::Deref for Time {
    type Target = timespec;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait FromStr<T, E> {
    fn from_str(str: &str) -> Result<T, E>;
}

impl FromStr<Duration, &str> for Duration {
    fn from_str(str: &str) -> Result<Duration, &'static str> {
        if str.len() < 2 {
            return Err("invalid duration");
        }
        match str.split_at_checked(str.len() - 1) {
            Some((num, unit)) => {
                let num = num.parse().map_err(|_| "invalid duration number")?;
                let dur = match unit {
                    "m" => Duration::from_mins(num),
                    "s" => Duration::from_secs(num),
                    _ => return Err("invalid duration unit"),
                };
                Ok(dur)
            }
            None => Err("invalid duration"),
        }
    }
}

impl Time {
    pub fn new(timespec: timespec) -> Self {
        Self(timespec)
    }
    pub fn from_duration(dur: Duration) -> Self {
        Self(timespec {
            tv_sec: dur.as_secs() as i64,
            tv_nsec: dur.subsec_nanos() as i64,
        })
    }
    fn is_set(&self) -> bool {
        self.tv_sec != 0 || self.tv_nsec != 0
    }
}

impl ops::Add for Time {
    type Output = Time;
    fn add(self, rhs: Self) -> Self::Output {
        const MAX_NANOSEC: i64 = 999999999;
        let tv_nsec = self.tv_nsec + rhs.tv_nsec;
        let tv_sec = self.tv_sec + rhs.tv_sec;
        if tv_nsec > MAX_NANOSEC {
            Self(timespec {
                tv_sec: tv_sec + 1,
                tv_nsec: tv_nsec - MAX_NANOSEC - 1,
            })
        } else {
            Self(timespec { tv_sec, tv_nsec })
        }
    }
}

impl cmp::Eq for Time {}

impl cmp::PartialEq for Time {
    fn eq(&self, other: &Self) -> bool {
        self.tv_nsec == other.tv_nsec && self.tv_sec == other.tv_sec
    }
}

impl cmp::PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for Time {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.tv_sec.cmp(&other.tv_sec) {
            cmp::Ordering::Equal => self.tv_nsec.cmp(&other.tv_nsec),
            ord => ord,
        }
    }
}

pub fn check(file: &File, timeout: Duration) -> Result<bool, ()> {
    let timeout = Time::from_duration(timeout);
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => errx!("fstat: {e}"),
    };
    if meta.uid() != 0
        || meta.gid() != c::getgid()
        || !meta.is_file()
        || (meta.permissions().mode() & 0o777) != 0o0000
    {
        errx!("timestamp uid, gid or mode wrong");
    }
    let stat = c::fstat(file.as_raw_fd())?;
    let expire_boot_time = Time::new(stat.st_atimespec);
    let expire_real_time = Time::new(stat.st_mtimespec);
    // this timestamp was created but never set, invalid but no error
    if !expire_boot_time.is_set() || !expire_real_time.is_set() {
        return Ok(false);
    }
    let Ok(boot_time) = c::clock_gettime(libc::CLOCK_MONOTONIC_RAW) else {
        return Ok(false);
    };
    let Ok(real_time) = c::clock_gettime(libc::CLOCK_REALTIME) else {
        return Ok(false);
    };
    // check if timestamp is too old
    if expire_boot_time < boot_time || expire_real_time < real_time {
        return Ok(false);
    }
    // check if timestamp is too far in the future
    if expire_boot_time > boot_time + timeout || expire_real_time > real_time + timeout {
        warnx!("timestamp too far in the future");
        return Ok(false);
    }
    Ok(true)
}

pub fn set(file: &File, timeout: Duration) -> Result<(), ()> {
    let timeout = Time::from_duration(timeout);
    let boot_time = c::clock_gettime(libc::CLOCK_MONOTONIC_RAW)? + timeout;
    let real_time = c::clock_gettime(libc::CLOCK_REALTIME)? + timeout;
    c::futimens(file.as_raw_fd(), &[boot_time, real_time])
}

pub fn open(timeout: Duration) -> Result<File, ()> {
    // check the dir first
    match fs::metadata(TIMESTAMP_DIR) {
        Ok(meta) => {
            if !meta.is_dir() || meta.uid() != 0 || (meta.permissions().mode() & 0o777) != 0o700 {
                errx!("invalid timestamp dir");
            }
        }
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                errx!("timestamp dir: {e}");
            }
            if let Err(e) = fs::create_dir(TIMESTAMP_DIR)
                .and_then(|_| fs::set_permissions(TIMESTAMP_DIR, Permissions::from_mode(0o700)))
            {
                errx!("create timestamp dir at {TIMESTAMP_DIR}: {e}");
            }
        }
    }
    let path = get_path()?;
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => {
            // check the file
            check(&file, timeout)?;
            Ok(file)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // create a new file
            // we use temp file here, to avoid the file being used before
            // setting correct timestamp
            let tmp_path = Path::new(TIMESTAMP_DIR).join(format!(".tmp-{}", c::getpid()));
            let file = match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o000)
                .open(&tmp_path)
            {
                Ok(f) => f,
                Err(e) => errx!("create timestamp file: {e}"),
            };
            if let Err(e) = file
                .set_times(
                    FileTimes::new()
                        .set_accessed(SystemTime::UNIX_EPOCH)
                        .set_modified(SystemTime::UNIX_EPOCH),
                )
                .and_then(|_| c::fchown(file.as_raw_fd(), 0, c::getgid()))
                .and_then(|_| fs::rename(&tmp_path, path))
            {
                let _ = fs::remove_file(tmp_path);
                errx!("set timestamp file: {e}");
            }
            Ok(file)
        }
        Err(e) => errx!("open timestamp file: {}: {e}", path.display()),
    }
}
