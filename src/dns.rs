use crate::DKIMError;
use ark_std::boxed::Box;
use ark_std::string::String;
use ark_std::sync::Arc;
use ark_std::vec::Vec;
use futures::future::BoxFuture;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::TokioAsyncResolver;

/// A trait for entities that perform DNS resolution.
pub trait Lookup: Sync + Send {
    fn lookup_txt<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<String>, DKIMError>>;
}

fn to_lookup_error(err: ResolveError) -> DKIMError {
    match err.kind() {
        ResolveErrorKind::NoRecordsFound { .. } => DKIMError::NoKeyForSignature,
        _ => DKIMError::KeyUnavailable(format!("failed to query DNS: {}", err)),
    }
}

// Technically we should be able to implemement Lookup for TokioAsyncResolver
// directly but it's failing for some reason.
struct TokioAsyncResolverWrapper {
    inner: TokioAsyncResolver,
}
impl Lookup for TokioAsyncResolverWrapper {
    fn lookup_txt<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<String>, DKIMError>> {
        Box::pin(async move {
            self.inner
                .txt_lookup(name)
                .await
                .map_err(to_lookup_error)?
                .into_iter()
                .map(|txt| {
                    Ok(txt
                        .iter()
                        .map(|data| String::from_utf8_lossy(data))
                        .collect())
                })
                .collect()
        })
    }
}

pub fn from_tokio_resolver(resolver: TokioAsyncResolver) -> Arc<dyn Lookup> {
    Arc::new(TokioAsyncResolverWrapper { inner: resolver })
}
