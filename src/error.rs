use regex_automata::Error as AutomatonError;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Regex must have bounded size")]
    InfiniteRegex,
    #[error("Error building automation")]
    AutomatonError(#[from] AutomatonError),
    #[error("Fiestal must have odd number of rounds")]
    EvenFiestalRounds,
    #[error("Ouput regex must have number of variants greater than or equal to input regex")]
    OutputDomainTooSmall,
    #[error("Invalid input value {0}")]
    InvalidInput(String),
    #[error("Invalid output offset {0}")]
    InvalidOutputOffset(u128),
    #[error(transparent)]
    InvalidStringBytes(#[from] FromUtf8Error),
    #[error("Invalid key length {0}")]
    InvalidKeyLength(usize),
    #[error("Invalid key expansion length")]
    InvalidKeyExpansion(usize),
    #[error("Regex domain is greater than usize::MAX in size")]
    DomainTooBig,
}
