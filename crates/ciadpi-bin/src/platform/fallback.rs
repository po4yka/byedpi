use std::io;
use std::net::TcpStream;

use socket2::SockRef;

fn set_stream_ttl_best_effort(stream: &TcpStream, ttl: u8) {
    let socket = SockRef::from(stream);
    let _ = socket.set_ttl(ttl as u32);
    let _ = socket.set_unicast_hops_v6(ttl as u32);
}

pub fn send_fake_tcp_best_effort(
    stream: &TcpStream,
    fake_prefix: &[u8],
    ttl: u8,
    md5sig: bool,
    default_ttl: u8,
    set_tcp_md5sig: fn(&TcpStream, u16) -> io::Result<()>,
) -> io::Result<()> {
    if ttl != 0 {
        set_stream_ttl_best_effort(stream, ttl);
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
        set_stream_ttl_best_effort(stream, default_ttl);
    }
    Ok(())
}
