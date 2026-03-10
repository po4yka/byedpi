use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn rust_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ciadpi")
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn unique_log_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ciadpi-runtime-integration-{}-{nanos}.log",
        std::process::id()
    ))
}

fn recv_exact(stream: &mut TcpStream, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    stream.read_exact(&mut buf).expect("read exact bytes");
    buf
}

fn recv_socks5_reply(stream: &mut TcpStream) -> Vec<u8> {
    let mut reply = recv_exact(stream, 4);
    let tail = match reply[3] {
        0x01 => recv_exact(stream, 6),
        0x04 => recv_exact(stream, 18),
        0x03 => {
            let mut tail = recv_exact(stream, 1);
            let size = tail[0] as usize;
            tail.extend(recv_exact(stream, size + 2));
            tail
        }
        atyp => panic!("unsupported SOCKS5 reply ATYP: {atyp}"),
    };
    reply.extend(tail);
    reply
}

fn socks_auth(proxy_port: u16) -> TcpStream {
    let mut stream =
        TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port)).expect("connect to proxy");
    stream
        .write_all(b"\x05\x01\x00")
        .expect("write auth negotiation");
    assert_eq!(recv_exact(&mut stream, 2), b"\x05\x00");
    stream
}

fn socks_connect(proxy_port: u16, dst_port: u16) -> TcpStream {
    let mut stream = socks_auth(proxy_port);
    let mut request = Vec::from([0x05, 0x01, 0x00, 0x01]);
    request.extend(Ipv4Addr::LOCALHOST.octets());
    request.extend(dst_port.to_be_bytes());
    stream.write_all(&request).expect("write socks5 connect");
    let reply = recv_socks5_reply(&mut stream);
    assert_eq!(reply[1], 0, "SOCKS5 connect failed: {reply:?}");
    stream
}

fn socks_connect_domain(proxy_port: u16, host: &str, dst_port: u16) -> (TcpStream, Vec<u8>) {
    let mut stream = socks_auth(proxy_port);
    let host_bytes = host.as_bytes();
    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend([0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    request.extend(host_bytes);
    request.extend(dst_port.to_be_bytes());
    stream
        .write_all(&request)
        .expect("write socks5 domain connect");
    let reply = recv_socks5_reply(&mut stream);
    (stream, reply)
}

fn http_connect(proxy_port: u16, dst_port: u16) -> TcpStream {
    let mut stream =
        TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port)).expect("connect to proxy");
    write!(
        stream,
        "CONNECT 127.0.0.1:{dst_port} HTTP/1.1\r\nHost: 127.0.0.1:{dst_port}\r\n\r\n"
    )
    .expect("write http connect");
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    while !response.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut chunk).expect("read http connect reply");
        assert_ne!(read, 0, "http connect response closed early");
        response.extend_from_slice(&chunk[..read]);
    }
    let response = String::from_utf8(response).expect("utf8 http connect reply");
    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "http connect failed: {response}"
    );
    stream
}

struct EchoServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl EchoServer {
    fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind echo server");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking echo listener");
        let addr = listener.local_addr().expect("echo listener addr");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        thread::spawn(move || {
                            let mut buf = [0u8; 4096];
                            loop {
                                match stream.read(&mut buf) {
                                    Ok(0) => return,
                                    Ok(read) => {
                                        if stream.write_all(&buf[..read]).is_err() {
                                            return;
                                        }
                                    }
                                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                                    Err(_) => return,
                                }
                            }
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("join echo listener");
        }
    }
}

struct ProxyProcess {
    port: u16,
    child: Child,
    log_path: PathBuf,
}

impl ProxyProcess {
    fn start(extra_args: &[&str]) -> Self {
        let port = free_port();
        let log_path = unique_log_path();
        let stdout = File::create(&log_path).expect("create proxy log");
        let stderr = stdout.try_clone().expect("clone proxy log");
        let mut command = Command::new(rust_bin());
        command
            .arg("-i")
            .arg("127.0.0.1")
            .arg("-p")
            .arg(port.to_string())
            .arg("-I")
            .arg("127.0.0.1")
            .args(extra_args)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = command.spawn().expect("spawn proxy");
        let mut process = Self {
            port,
            child,
            log_path,
        };
        process.wait_ready();
        process
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(probe) = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)) {
                let _ = probe.shutdown(Shutdown::Both);
                return;
            }
            if self.child.try_wait().expect("poll proxy status").is_some() {
                panic!("proxy exited early:\n{}", self.read_log());
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("proxy did not start:\n{}", self.read_log());
    }

    fn read_log(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        if self.child.try_wait().expect("poll proxy status").is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = fs::remove_file(&self.log_path);
    }
}

#[test]
fn socks5_echo_round_trip() {
    let echo = EchoServer::start();
    let proxy = ProxyProcess::start(&[]);
    let mut stream = socks_connect(proxy.port, echo.port());
    let payload = b"plain socks payload";
    stream.write_all(payload).expect("write echo payload");
    assert_eq!(recv_exact(&mut stream, payload.len()), payload);
}

#[test]
fn http_connect_echo_round_trip() {
    let echo = EchoServer::start();
    let proxy = ProxyProcess::start(&["-G"]);
    let mut stream = http_connect(proxy.port, echo.port());
    let payload = b"http connect payload";
    stream.write_all(payload).expect("write connect payload");
    assert_eq!(recv_exact(&mut stream, payload.len()), payload);
}

#[test]
fn no_domain_rejects_domain_requests() {
    let proxy = ProxyProcess::start(&["-N"]);
    let (_stream, reply) = socks_connect_domain(proxy.port, "localhost", 80);
    assert_ne!(reply[1], 0, "domain request unexpectedly succeeded: {reply:?}");
}

#[test]
fn connect_failure_does_not_create_a_working_tunnel() {
    let closed_port = free_port();
    let proxy = ProxyProcess::start(&[]);
    let mut stream = socks_auth(proxy.port);
    let mut request = Vec::from([0x05, 0x01, 0x00, 0x01]);
    request.extend(Ipv4Addr::LOCALHOST.octets());
    request.extend(closed_port.to_be_bytes());
    stream
        .write_all(&request)
        .expect("write socks5 connect request");
    let reply = recv_socks5_reply(&mut stream);
    if reply[1] != 0 {
        return;
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    stream
        .write_all(b"closed-port-probe")
        .expect("write probe payload");
    let mut buf = [0u8; 1];
    match stream.read(&mut buf) {
        Ok(0) => {}
        Err(_) => {}
        Ok(read) => panic!("connect failure yielded a working tunnel: read {read} bytes"),
    }
}
