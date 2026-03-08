#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesyncMode {
    Split,
    Disorder,
    Oob,
    Disoob,
    Fake,
}
