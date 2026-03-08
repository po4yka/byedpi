use std::io;
use std::net::TcpStream;

pub fn set_tcp_md5sig(_stream: &TcpStream, _key_len: u16) -> io::Result<()> {
    Ok(())
}
