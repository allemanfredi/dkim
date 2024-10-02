use ark_std::string::String;
/// DKIM error status
use core::fmt;
pub enum Status {
    Permfail,
    Tempfail,
}

/// DKIM errors
#[derive(Debug, Clone, PartialEq)]
pub enum DKIMError {
    UnsupportedHashAlgorithm(String),
    UnsupportedCanonicalizationType(String),
    SignatureSyntaxError(String),
    SignatureMissingRequiredTag(&'static str),
    IncompatibleVersion,
    DomainMismatch,
    FromFieldNotSigned,
    SignatureExpired,
    UnacceptableSignatureHeader,
    UnsupportedQueryMethod,
    KeyUnavailable(String),
    UnknownInternalError(String),
    NoKeyForSignature,
    KeySyntaxError,
    KeyIncompatibleVersion,
    InappropriateKeyAlgorithm,
    SignatureDidNotVerify,
    BodyHashDidNotVerify,
    MalformedBody,
    FailedToSign(String),
    BuilderError(&'static str),
}

impl fmt::Display for DKIMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DKIMError::UnsupportedHashAlgorithm(value) => {
                write!(f, "unsupported hash algorithm: {}", value)
            }
            DKIMError::UnsupportedCanonicalizationType(value) => {
                write!(f, "unsupported canonicalization: {}", value)
            }
            DKIMError::SignatureSyntaxError(err) => {
                write!(f, "signature syntax error: {}", err)
            }
            DKIMError::SignatureMissingRequiredTag(name) => {
                write!(f, "signature missing required tag ({})", name)
            }
            DKIMError::IncompatibleVersion => write!(f, "incompatible version"),
            DKIMError::DomainMismatch => write!(f, "domain mismatch"),
            DKIMError::FromFieldNotSigned => write!(f, "From field not signed"),
            DKIMError::SignatureExpired => write!(f, "signature expired"),
            DKIMError::UnacceptableSignatureHeader => {
                write!(f, "unacceptable signature header")
            }
            DKIMError::UnsupportedQueryMethod => write!(f, "unsupported query method"),
            DKIMError::KeyUnavailable(err) => write!(f, "key unavailable: {}", err),
            DKIMError::UnknownInternalError(err) => write!(f, "internal error: {}", err),
            DKIMError::NoKeyForSignature => write!(f, "no key for signature"),
            DKIMError::KeySyntaxError => write!(f, "key syntax error"),
            DKIMError::KeyIncompatibleVersion => write!(f, "key incompatible version"),
            DKIMError::InappropriateKeyAlgorithm => write!(f, "inappropriate key algorithm"),
            DKIMError::SignatureDidNotVerify => write!(f, "signature did not verify"),
            DKIMError::BodyHashDidNotVerify => write!(f, "body hash did not verify"),
            DKIMError::MalformedBody => write!(f, "malformed email body"),
            DKIMError::FailedToSign(err) => write!(f, "failed to sign: {}", err),
            DKIMError::BuilderError(err) => write!(f, "failed to build object: {}", err),
        }
    }
}

impl DKIMError {
    pub fn status(self) -> Status {
        use DKIMError::*;
        match self {
            SignatureSyntaxError(_)
            | SignatureMissingRequiredTag(_)
            | IncompatibleVersion
            | DomainMismatch
            | FromFieldNotSigned
            | SignatureExpired
            | UnacceptableSignatureHeader
            | UnsupportedQueryMethod
            | NoKeyForSignature
            | KeySyntaxError
            | KeyIncompatibleVersion
            | InappropriateKeyAlgorithm
            | SignatureDidNotVerify
            | BodyHashDidNotVerify
            | MalformedBody
            | UnsupportedCanonicalizationType(_)
            | UnsupportedHashAlgorithm(_) => Status::Permfail,
            KeyUnavailable(_) | UnknownInternalError(_) => Status::Tempfail,
            BuilderError(_) | FailedToSign(_) => unreachable!(),
        }
    }
}
