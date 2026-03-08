#![forbid(unsafe_code)]

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigOracle {
    pub args: Vec<String>,
    pub cache_file: Option<PathBuf>,
}

impl ConfigOracle {
    pub fn new(args: impl IntoIterator<Item = String>) -> Self {
        Self {
            args: args.into_iter().collect(),
            cache_file: None,
        }
    }
}
