use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
mod stub;

pub fn detect_default_ttl() -> io::Result<u8> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    let ttl = socket.ttl()?;
    u8::try_from(ttl)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "socket ttl exceeds u8"))
}

#[cfg(target_os = "linux")]
pub fn enable_tcp_fastopen_connect<T: AsRawFd>(socket: &T) -> io::Result<()> {
    linux::enable_tcp_fastopen_connect(socket)
}

#[cfg(not(target_os = "linux"))]
pub fn enable_tcp_fastopen_connect<T: AsRawFd>(_socket: &T) -> io::Result<()> {
    stub::enable_tcp_fastopen_connect()
}

#[cfg(target_os = "linux")]
pub fn set_tcp_md5sig(stream: &TcpStream, key_len: u16) -> io::Result<()> {
    linux::set_tcp_md5sig(stream, key_len)
}

#[cfg(not(target_os = "linux"))]
pub fn set_tcp_md5sig(stream: &TcpStream, key_len: u16) -> io::Result<()> {
    stub::set_tcp_md5sig(stream, key_len)
}

#[cfg(target_os = "linux")]
pub fn protect_socket<T: AsRawFd>(socket: &T, path: &str) -> io::Result<()> {
    linux::protect_socket(socket, path)
}

#[cfg(not(target_os = "linux"))]
pub fn protect_socket<T: AsRawFd>(socket: &T, path: &str) -> io::Result<()> {
    stub::protect_socket(socket, path)
}

#[cfg(target_os = "linux")]
pub fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    linux::original_dst(stream)
}

#[cfg(not(target_os = "linux"))]
pub fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    stub::original_dst(stream)
}

#[cfg(target_os = "linux")]
pub fn attach_drop_sack(stream: &TcpStream) -> io::Result<()> {
    linux::attach_drop_sack(stream)
}

#[cfg(not(target_os = "linux"))]
pub fn attach_drop_sack(stream: &TcpStream) -> io::Result<()> {
    stub::attach_drop_sack(stream)
}

#[cfg(target_os = "linux")]
pub fn detach_drop_sack(stream: &TcpStream) -> io::Result<()> {
    linux::detach_drop_sack(stream)
}

#[cfg(not(target_os = "linux"))]
pub fn detach_drop_sack(stream: &TcpStream) -> io::Result<()> {
    stub::detach_drop_sack(stream)
}

#[cfg(target_os = "linux")]
pub fn send_fake_tcp(
    stream: &TcpStream,
    original_prefix: &[u8],
    fake_prefix: &[u8],
    ttl: u8,
    md5sig: bool,
    default_ttl: u8,
    wait_send: bool,
    await_interval: Duration,
) -> io::Result<()> {
    linux::send_fake_tcp(
        stream,
        original_prefix,
        fake_prefix,
        ttl,
        md5sig,
        default_ttl,
        wait_send,
        await_interval,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn send_fake_tcp(
    stream: &TcpStream,
    _original_prefix: &[u8],
    fake_prefix: &[u8],
    ttl: u8,
    md5sig: bool,
    default_ttl: u8,
    _wait_send: bool,
    _await_interval: Duration,
) -> io::Result<()> {
    stub::send_fake_tcp(stream, fake_prefix, ttl, md5sig, default_ttl)
}

#[cfg(target_os = "linux")]
pub fn wait_tcp_stage(
    stream: &TcpStream,
    wait_send: bool,
    await_interval: Duration,
) -> io::Result<()> {
    linux::wait_tcp_stage(stream, wait_send, await_interval)
}

#[cfg(not(target_os = "linux"))]
pub fn wait_tcp_stage(
    stream: &TcpStream,
    wait_send: bool,
    await_interval: Duration,
) -> io::Result<()> {
    stub::wait_tcp_stage(stream, wait_send, await_interval)
}
