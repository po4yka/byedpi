#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Handshake,
    Connected,
    Closed,
}
