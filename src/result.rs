#![allow(unknown_lints)] // non_local_definitions isn't in Rust 1.70
#![allow(non_local_definitions)]
//! Error types that can be emitted from this library

use displaydoc::Display;
use thiserror::Error;

use std::error::Error;
use std::fmt;
use std::io;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;

/// Generic result type with ZipError as its error variant
pub type ZipResult<T> = Result<T, ZipError>;

/// Error type for Zip
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ZipError {
    /// i/o error: {0}
    Io(#[from] io::Error),

    /// invalid Zip archive: {0}
    InvalidArchive(&'static str),

    /// unsupported Zip archive: {0}
    UnsupportedArchive(&'static str),

    /// specified file not found in archive
    FileNotFound,

    /// The password provided is incorrect
    InvalidPassword,
}

impl ZipError {
    /// The text used as an error when a password is required and not supplied
    ///
    /// ```rust,no_run
    /// # use zip::result::ZipError;
    /// # let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&[])).unwrap();
    /// match archive.by_index(1) {
    ///     Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)) => eprintln!("a password is needed to unzip this file"),
    ///     _ => (),
    /// }
    /// # ()
    /// ```
    pub const PASSWORD_REQUIRED: &'static str = "Password required to decrypt file";
}

impl From<ZipError> for io::Error {
    fn from(err: ZipError) -> io::Error {
        let kind = match &err {
            ZipError::Io(err) => err.kind(),
            ZipError::InvalidArchive(_) => io::ErrorKind::InvalidData,
            ZipError::UnsupportedArchive(_) => io::ErrorKind::Unsupported,
            ZipError::FileNotFound => io::ErrorKind::NotFound,
            ZipError::InvalidPassword => io::ErrorKind::InvalidInput,
        };

        io::Error::new(kind, err)
    }
}

impl From<DateTimeRangeError> for ZipError {
    fn from(_: DateTimeRangeError) -> Self {
        ZipError::InvalidArchive("Invalid date or time")
    }
}

impl From<FromUtf8Error> for ZipError {
    fn from(_: FromUtf8Error) -> Self {
        ZipError::InvalidArchive("Invalid UTF-8")
    }
}

/// Error type for time parsing
#[derive(Debug)]
pub struct DateTimeRangeError;

// TryFromIntError is also an out-of-range error.
impl From<TryFromIntError> for DateTimeRangeError {
    fn from(_value: TryFromIntError) -> Self {
        DateTimeRangeError
    }
}

impl fmt::Display for DateTimeRangeError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "a date could not be represented within the bounds the MS-DOS date range (1980-2107)"
        )
    }
}

impl Error for DateTimeRangeError {}

/// Represents a potentially untrusted untrustworthy value.
///
/// An attacker might be able to control (part) of the returned value.
/// Take special care processing this data.
///
/// See the method documentation of the function returning this value
pub struct UntrustedValue<T> {
    value: T,
}

impl<T> UntrustedValue<T> {
    /// Be sure that you carefully handle the returned value since
    /// it may be controllable by a malicious actor.
    ///
    /// See the method documentation of the function returning this value
    pub fn use_untrusted_value(self) -> T {
        self.value
    }

    /// Wraps the provided value as UntrustedValue
    pub fn wrap(value: T) -> Self {
        UntrustedValue {value}
    }
}

impl<T> From<T> for UntrustedValue<T> {
    fn from(value: T) -> Self {
        UntrustedValue::wrap(value)
    }
}

/// Represents a value that might be untrusted. See UntrustedValue for more information.
pub enum MaybeUntrusted<T> {
    /// Trusted value variant
    Ok(T),
    /// Untrusted value variant
    Untrusted(UntrustedValue<T>),
}

impl<T> MaybeUntrusted<T> {
    /// Be sure that you carefully handle the returned value since
    /// it may be controllable by a malicious actor (when it is a MaybeUntrusted::Untrusted).
    ///
    /// See the method documentation of the function returning this value
    pub fn use_untrusted_value(self) -> T {
        match self {
            MaybeUntrusted::Ok(value) => value,
            MaybeUntrusted::Untrusted(value) => value.use_untrusted_value(),
        }
    }

    /// Unwraps the value if values is not untrusted, if untrusted returns the provided error message
    pub fn unwrap_or_error(self, error: &'static str) -> Result<T, ZipError> {
        match self {
            MaybeUntrusted::Ok(value) => Ok(value),
            MaybeUntrusted::Untrusted(_) => Err(ZipError::InvalidArchive(error)),
        }
    }

    /// Returns true if the value is untrusted
    pub fn is_untrusted(&self) -> bool {
        match self {
            MaybeUntrusted::Ok(_) => false,
            MaybeUntrusted::Untrusted(_) => true,
        }
    }

    /// Returns true if the value is not untrusted
    pub fn is_ok(&self) -> bool {
        !self.is_untrusted()
    }

    /// Wraps the provided values as Untrusted
    pub fn wrap_untrusted(value: T) -> Self {
        MaybeUntrusted::Untrusted(value.into())
    }

    /// Wraps the provided values as Ok
    pub fn wrap_ok(value: T) -> Self {
        MaybeUntrusted::Ok(value)
    }

    /// Wraps the provided value as maybe untrusted, according to given boolean
    pub fn wrap(value: T, untrusted: bool) -> Self {
        match untrusted {
            true => Self::wrap_untrusted(value),
            false => Self::wrap_ok(value),
        }
    }
}

impl<T> From<UntrustedValue<T>> for MaybeUntrusted<T> {
    fn from(value: UntrustedValue<T>) -> Self {
        MaybeUntrusted::Untrusted(value)
    }
}
