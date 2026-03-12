use std::future::Future;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use async_trait::async_trait;

use crate::error::DIDCommServiceError;
use crate::handler::extractor::Extensions;
use crate::handler::{FromMessageParts, HandlerContext, MessageParts};
use crate::response::DIDCommResponse;

/// Route-level message handler with automatic argument extraction.
///
/// Prefer using `handler_fn` with a plain async function rather than implementing
/// this trait directly. Arguments are extracted from `MessageParts` — each of
/// `Message` and `UnpackMetadata` can only be extracted once per invocation.
#[async_trait]
pub trait MessageHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: UnpackMetadata,
        extensions: Extensions,
    ) -> Result<Option<DIDCommResponse>, DIDCommServiceError>;
}

type HandlerResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

macro_rules! impl_handler {
    ($($ty:ident),*) => {
        #[async_trait]
        impl<F, Fut, $($ty,)*> MessageHandler for HandlerFn<F, ($($ty,)*)>
        where
            F: Fn($($ty,)*) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = HandlerResult> + Send + 'static,
            $($ty: FromMessageParts + 'static,)*
        {
            #[allow(unused_variables, unused_mut, non_snake_case)]
            async fn handle(
                &self,
                ctx: HandlerContext,
                message: Message,
                meta: UnpackMetadata,
                extensions: Extensions,
            ) -> HandlerResult {
                let mut parts = MessageParts {
                    ctx,
                    message: Some(message),
                    meta: Some(meta),
                    extensions,
                };
                $(let $ty = $ty::from_parts(&mut parts)?;)*
                (self.f)($($ty,)*).await
            }
        }
    };
}

pub struct HandlerFn<F, T> {
    f: F,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl_handler!();
impl_handler!(T1);
impl_handler!(T1, T2);
impl_handler!(T1, T2, T3);
impl_handler!(T1, T2, T3, T4);
impl_handler!(T1, T2, T3, T4, T5);

pub fn handler_fn<F, T>(f: F) -> HandlerFn<F, T> {
    HandlerFn {
        f,
        _marker: std::marker::PhantomData,
    }
}
