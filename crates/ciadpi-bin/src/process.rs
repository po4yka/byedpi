#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ciadpi_config::RuntimeConfig;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub struct ProcessGuard {
    #[cfg(unix)]
    _pid_file: Option<PidFileGuard>,
}

impl ProcessGuard {
    pub fn prepare(config: &RuntimeConfig) -> io::Result<Self> {
        SHUTDOWN.store(false, Ordering::Relaxed);
        #[cfg(unix)]
        {
            if config.daemonize {
                daemonize()?;
            }
            install_signal_handlers()?;
            let pid_file = match config.pid_file.as_deref() {
                Some(path) => Some(PidFileGuard::create(Path::new(path))?),
                None => None,
            };
            return Ok(Self { _pid_file: pid_file });
        }

        #[cfg(not(unix))]
        {
            if config.daemonize || config.pid_file.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "daemon and pidfile support are unavailable on this platform",
                ));
            }
            Ok(Self {})
        }
    }
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

#[cfg(unix)]
extern "C" fn handle_signal(_signal: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
fn install_signal_handlers() -> io::Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let prev = unsafe { libc::signal(signal, handle_signal as libc::sighandler_t) };
        if prev == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
#[allow(deprecated)]
fn daemonize() -> io::Result<()> {
    let rc = unsafe { libc::daemon(0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
struct PidFileGuard {
    file: File,
    path: PathBuf,
}

#[cfg(unix)]
impl PidFileGuard {
    fn create(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        let mut lock = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_CUR as i16,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &mut lock) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        file.set_len(0)?;
        write!(file, "{}", std::process::id())?;
        file.flush()?;

        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }
}

#[cfg(unix)]
impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = self.file.flush();
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
use std::os::fd::AsRawFd;
