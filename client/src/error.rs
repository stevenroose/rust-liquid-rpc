
use std::{error, fmt, io};

use bitcoin;
use elements;
use bitcoin::hashes::hex;
use bitcoin::secp256k1;
use jsonrpc;
use serde_json;

/// The error type for errors produced in this library.
#[derive(Debug)]
pub enum Error {
    JsonRpc(jsonrpc::error::Error),
    Hex(hex::Error),
    Json(serde_json::error::Error),
    BitcoinSerialization(bitcoin::consensus::encode::Error),
    ElementsSerialization(elements::encode::Error),
    Secp256k1(secp256k1::Error),
    Io(io::Error),
    InvalidAmount(bitcoin::util::amount::ParseAmountError),
    InvalidCookieFile,
    /// The JSON result had an unexpected structure.
    UnexpectedStructure,
}

impl From<jsonrpc::error::Error> for Error {
    fn from(e: jsonrpc::error::Error) -> Error {
        Error::JsonRpc(e)
    }
}

impl From<hex::Error> for Error {
    fn from(e: hex::Error) -> Error {
        Error::Hex(e)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Error {
        Error::Json(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(e: bitcoin::consensus::encode::Error) -> Error {
        Error::BitcoinSerialization(e)
    }
}

impl From<elements::encode::Error> for Error {
    fn from(e: elements::encode::Error) -> Error {
        Error::ElementsSerialization(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<bitcoin::util::amount::ParseAmountError> for Error {
    fn from(e: bitcoin::util::amount::ParseAmountError) -> Error {
        Error::InvalidAmount(e)
    }
}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Error {
        match e {
            bitcoincore_rpc::Error::JsonRpc(e) => Error::JsonRpc(e),
            bitcoincore_rpc::Error::Hex(e) => Error::Hex(e),
            bitcoincore_rpc::Error::Json(e) => Error::Json(e),
            bitcoincore_rpc::Error::BitcoinSerialization(e) => Error::BitcoinSerialization(e),
            bitcoincore_rpc::Error::Secp256k1(e) => Error::Secp256k1(e),
            bitcoincore_rpc::Error::Io(e) => Error::Io(e),
            bitcoincore_rpc::Error::InvalidAmount(e) => Error::InvalidAmount(e),
            bitcoincore_rpc::Error::InvalidCookieFile => Error::InvalidCookieFile,
            bitcoincore_rpc::Error::UnexpectedStructure => Error::UnexpectedStructure,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::JsonRpc(ref e) => write!(f, "JSON-RPC error: {}", e),
            Error::Hex(ref e) => write!(f, "hex decode error: {}", e),
            Error::Json(ref e) => write!(f, "JSON error: {}", e),
            Error::BitcoinSerialization(ref e) => write!(f, "Bitcoin serialization error: {}", e),
            Error::ElementsSerialization(ref e) => write!(f, "Elements serialization error: {}", e),
            Error::Secp256k1(ref e) => write!(f, "secp256k1 error: {}", e),
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::InvalidAmount(ref e) => write!(f, "invalid amount: {}", e),
            Error::InvalidCookieFile => write!(f, "invalid cookie file"),
            Error::UnexpectedStructure => write!(f, "the JSON result had an unexpected structure"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "bitcoincore-rpc error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::JsonRpc(ref e) => Some(e),
            Error::Hex(ref e) => Some(e),
            Error::Json(ref e) => Some(e),
            Error::BitcoinSerialization(ref e) => Some(e),
            Error::ElementsSerialization(ref e) => Some(e),
            Error::Secp256k1(ref e) => Some(e),
            Error::Io(ref e) => Some(e),
            _ => None,
        }
    }
}
