use std::io;
use std::net::{SocketAddr, TcpStream};

pub fn enable_tcp_fastopen_connect() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tcp fast open connect is linux-only",
    ))
}

pub fn set_tcp_md5sig(_stream: &TcpStream, _key_len: u16) -> io::Result<()> {
    Ok(())
}

pub fn protect_socket<T>(_socket: &T, _path: &str) -> io::Result<()> {
    Ok(())
}

pub fn original_dst(_stream: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "transparent proxy mode is linux-only",
    ))
}

pub fn attach_drop_sack(_stream: &TcpStream) -> io::Result<()> {
    Ok(())
}

pub fn detach_drop_sack(_stream: &TcpStream) -> io::Result<()> {
    Ok(())
}

pub fn send_fake_tcp(
    stream: &TcpStream,
    fake_prefix: &[u8],
    ttl: u8,
    md5sig: bool,
    default_ttl: u8,
) -> io::Result<()> {
    if ttl != 0 {
        let socket = socket2::SockRef::from(stream);
        let _ = socket.set_ttl(ttl as u32);
        let _ = socket.set_unicast_hops_v6(ttl as u32);
    }
    if md5sig {
        let _ = set_tcp_md5sig(stream, 5);
    }
    let mut writer = stream.try_clone()?;
    std::io::Write::write_all(&mut writer, fake_prefix)?;
    if md5sig {
        let _ = set_tcp_md5sig(stream, 0);
    }
    if default_ttl != 0 {
        let socket = socket2::SockRef::from(stream);
        let _ = socket.set_ttl(default_ttl as u32);
        let _ = socket.set_unicast_hops_v6(default_ttl as u32);
    }
    Ok(())
}

pub fn wait_tcp_stage(
    _stream: &TcpStream,
    _wait_send: bool,
    _await_interval: std::time::Duration,
) -> io::Result<()> {
    Ok(())
}
