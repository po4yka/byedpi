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
    super::fallback::send_fake_tcp_best_effort(
        stream,
        fake_prefix,
        ttl,
        md5sig,
        default_ttl,
        set_tcp_md5sig,
    )
}

pub fn wait_tcp_stage(
    _stream: &TcpStream,
    _wait_send: bool,
    _await_interval: std::time::Duration,
) -> io::Result<()> {
    Ok(())
}
