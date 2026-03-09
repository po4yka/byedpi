use std::env;
use std::ffi::OsString;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::process;

const SERVICE_NAME: &str = "ByeDPI";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

static SERVICE_ARGS: OnceLock<Vec<String>> = OnceLock::new();
static SERVICE_RUNNER: OnceLock<fn(Vec<String>) -> i32> = OnceLock::new();
static SERVICE_EXIT_CODE: AtomicI32 = AtomicI32::new(1);

define_windows_service!(ffi_service_main, service_main);

pub fn maybe_run_as_service(
    args: &[String],
    runner: fn(Vec<String>) -> i32,
) -> io::Result<Option<i32>> {
    if SERVICE_ARGS.set(args.to_vec()).is_err() || SERVICE_RUNNER.set(runner).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "windows service dispatcher already initialized",
        ));
    }
    SERVICE_EXIT_CODE.store(1, Ordering::Relaxed);

    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(Some(SERVICE_EXIT_CODE.load(Ordering::Relaxed))),
        Err(err) if service_dispatch_error(&err) == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) => {
            Ok(None)
        }
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}

pub fn service_main(_arguments: Vec<OsString>) {
    SERVICE_EXIT_CODE.store(run_service(), Ordering::Relaxed);
}

fn run_service() -> i32 {
    let _ = set_service_working_directory();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                process::request_shutdown();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let Ok(status_handle) = service_control_handler::register(SERVICE_NAME, event_handler) else {
        return 1;
    };
    if status_handle.set_service_status(running_status()).is_err() {
        return 1;
    }

    let exit_code = run_saved_args();
    let _ = status_handle.set_service_status(stopped_status(exit_code));
    exit_code
}

fn running_status() -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn stopped_status(exit_code: i32) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(exit_code.max(0) as u32),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn run_saved_args() -> i32 {
    let Some(runner) = SERVICE_RUNNER.get().copied() else {
        return 1;
    };
    let args = SERVICE_ARGS.get().cloned().unwrap_or_default();
    runner(args)
}

fn set_service_working_directory() -> io::Result<()> {
    let exe = env::current_exe()?;
    let Some(parent) = exe.parent() else {
        return Ok(());
    };
    env::set_current_dir(parent)
}

fn service_dispatch_error(err: &windows_service::Error) -> Option<i32> {
    match err {
        windows_service::Error::Winapi(source) => source.raw_os_error(),
        _ => None,
    }
}

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
    _await_interval: Duration,
) -> io::Result<()> {
    Ok(())
}
