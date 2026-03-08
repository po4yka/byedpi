use std::io;
use std::mem::{size_of, zeroed};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use socket2::SockRef;

#[repr(C)]
struct TcpMd5Sig {
    addr: libc::sockaddr_storage,
    pad1: u16,
    key_len: u16,
    pad2: u32,
    key: [u8; 80],
}

pub fn set_tcp_md5sig(stream: &TcpStream, key_len: u16) -> io::Result<()> {
    if usize::from(key_len) > 80 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "md5 key length exceeds linux tcp_md5sig limit",
        ));
    }

    let fd = stream.as_raw_fd();
    let addr = peer_addr(fd)?;
    let md5 = TcpMd5Sig {
        addr,
        pad1: 0,
        key_len,
        pad2: 0,
        key: [0; 80],
    };

    // SAFETY: `md5` is a valid `tcp_md5sig`-compatible buffer and the file
    // descriptor refers to a live TCP socket owned by `stream`.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            (&md5 as *const TcpMd5Sig).cast(),
            size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn attach_drop_sack(stream: &TcpStream) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    let mut code = [
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x0000000c,
        },
        libc::sock_filter {
            code: 0x74,
            jt: 0,
            jf: 0,
            k: 0x00000004,
        },
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 3,
            k: 0x0000000b,
        },
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x00000022,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 0x00000005,
        },
        libc::sock_filter {
            code: 0x6,
            jt: 0,
            jf: 0,
            k: 0x00000000,
        },
        libc::sock_filter {
            code: 0x6,
            jt: 0,
            jf: 0,
            k: 0x00040000,
        },
    ];
    let prog = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };

    // SAFETY: `prog` points to a live in-process BPF program definition and
    // `fd` is a valid TCP socket descriptor owned by `stream`.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&prog as *const libc::sock_fprog).cast(),
            size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn detach_drop_sack(stream: &TcpStream) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    let nop = 0i32;
    // SAFETY: `nop` is a valid pointer-sized payload for `SO_DETACH_FILTER`
    // and `fd` is a live TCP socket descriptor.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DETACH_FILTER,
            (&nop as *const i32).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn send_fake_tcp(
    stream: &TcpStream,
    original_prefix: &[u8],
    fake_prefix: &[u8],
    ttl: u8,
    md5sig: bool,
    default_ttl: u8,
    _wait_send: bool,
    await_interval: Duration,
) -> io::Result<()> {
    if original_prefix.is_empty() {
        return Ok(());
    }

    let fd = stream.as_raw_fd();
    let region_len = original_prefix.len().max(fake_prefix.len());
    let region = alloc_region(region_len)?;
    let mut pipe_fds = [-1; 2];

    let result = (|| {
        write_region(region, fake_prefix, region_len);

        // SAFETY: `pipe_fds` points to storage for two file descriptors.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }

        set_stream_ttl(stream, ttl)?;
        if md5sig {
            set_tcp_md5sig(stream, 5)?;
        }

        let iov = libc::iovec {
            iov_base: region.cast(),
            iov_len: original_prefix.len(),
        };
        // SAFETY: `iov` references an anonymous writable mapping whose lifetime
        // extends until after the splice completes.
        let queued = unsafe { libc::vmsplice(pipe_fds[1], &iov, 1, libc::SPLICE_F_GIFT as libc::c_uint) };
        if queued < 0 {
            return Err(io::Error::last_os_error());
        }
        if queued as usize != original_prefix.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial vmsplice during fake tcp send",
            ));
        }

        let mut moved = 0usize;
        while moved < original_prefix.len() {
            // SAFETY: both descriptors are live, the source is a pipe end, and
            // the destination is the connected TCP socket referenced by `fd`.
            let chunk = unsafe {
                libc::splice(
                    pipe_fds[0],
                    ptr::null_mut(),
                    fd,
                    ptr::null_mut(),
                    original_prefix.len() - moved,
                    0,
                )
            };
            if chunk < 0 {
                return Err(io::Error::last_os_error());
            }
            if chunk == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial splice during fake tcp send",
                ));
            }
            moved += chunk as usize;
        }

        if md5sig {
            set_tcp_md5sig(stream, 0)?;
        }
        if default_ttl != 0 {
            set_stream_ttl(stream, default_ttl)?;
        }

        wait_until_no_notsent(fd, await_interval)?;
        write_region(region, original_prefix, region_len);
        Ok(())
    })();

    if pipe_fds[0] >= 0 {
        // SAFETY: file descriptor is valid when non-negative and owned here.
        unsafe {
            libc::close(pipe_fds[0]);
        }
    }
    if pipe_fds[1] >= 0 {
        // SAFETY: file descriptor is valid when non-negative and owned here.
        unsafe {
            libc::close(pipe_fds[1]);
        }
    }
    if md5sig {
        let _ = set_tcp_md5sig(stream, 0);
    }
    if default_ttl != 0 {
        let _ = set_stream_ttl(stream, default_ttl);
    }
    free_region(region, region_len);
    result
}

fn peer_addr(fd: libc::c_int) -> io::Result<libc::sockaddr_storage> {
    // SAFETY: `storage` is zero-initialized and `getpeername` writes at most
    // `len` bytes into it for the valid socket descriptor `fd`.
    let mut storage = unsafe { zeroed::<libc::sockaddr_storage>() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe { libc::getpeername(fd, (&mut storage as *mut libc::sockaddr_storage).cast(), &mut len) };
    if rc == 0 {
        Ok(storage)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_stream_ttl(stream: &TcpStream, ttl: u8) -> io::Result<()> {
    let socket = SockRef::from(stream);
    let ipv4 = socket.set_ttl(ttl as u32);
    let ipv6 = socket.set_unicast_hops_v6(ttl as u32);
    match (ipv4, ipv6) {
        (Ok(()), _) | (_, Ok(())) => Ok(()),
        (Err(err), _) => Err(err),
    }
}

fn tcp_has_notsent(fd: libc::c_int) -> io::Result<bool> {
    let mut outq = 0i32;
    // SAFETY: `outq` is a valid writable integer and `fd` is a live socket.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut outq) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(outq != 0)
}

fn wait_until_no_notsent(fd: libc::c_int, await_interval: Duration) -> io::Result<()> {
    let sleep_for = if await_interval.is_zero() {
        Duration::from_millis(1)
    } else {
        await_interval
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !tcp_has_notsent(fd)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for tcp send queue to drain",
            ));
        }
        thread::sleep(sleep_for);
    }
}

fn alloc_region(len: usize) -> io::Result<*mut u8> {
    // SAFETY: `mmap` is called with an anonymous private mapping request and
    // returns either a valid pointer or `MAP_FAILED`.
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr.cast())
    }
}

fn free_region(region: *mut u8, len: usize) {
    if !region.is_null() && len != 0 {
        // SAFETY: `region` was allocated by `mmap` with the same length.
        unsafe {
            libc::munmap(region.cast(), len);
        }
    }
}

fn write_region(region: *mut u8, data: &[u8], len: usize) {
    // SAFETY: `region` points to a writable mapping of `len` bytes.
    unsafe {
        ptr::write_bytes(region, 0, len);
        ptr::copy_nonoverlapping(data.as_ptr(), region, data.len().min(len));
    }
}
