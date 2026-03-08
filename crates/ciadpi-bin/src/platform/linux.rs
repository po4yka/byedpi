use std::io;
use std::mem::{size_of, zeroed};
use std::net::TcpStream;
use std::os::fd::AsRawFd;

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
