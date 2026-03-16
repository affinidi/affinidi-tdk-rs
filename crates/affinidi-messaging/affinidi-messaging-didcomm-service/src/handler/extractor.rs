use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

use affinidi_messaging_didcomm::{Message, UnpackMetadata};

use super::HandlerContext;
use crate::error::DIDCommServiceError;

#[derive(Default, Clone)]
pub struct Extensions {
    map: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl Extensions {
    pub fn insert<T: Send + Sync + 'static>(&mut self, val: T) {
        self.map.insert(TypeId::of::<T>(), Arc::new(val));
    }

    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|v| v.downcast_ref::<T>())
    }
}

pub struct MessageParts {
    pub ctx: HandlerContext,
    pub message: Option<Message>,
    pub meta: Option<UnpackMetadata>,
    pub extensions: Extensions,
}

/// Extract a value from the incoming message parts for use as a handler argument.
///
/// `Message` and `UnpackMetadata` are consumed on extraction — requesting the
/// same type twice in one handler will return an error.
pub trait FromMessageParts: Sized + Send {
    fn from_parts(parts: &mut MessageParts) -> Result<Self, DIDCommServiceError>;
}

impl FromMessageParts for HandlerContext {
    fn from_parts(parts: &mut MessageParts) -> Result<Self, DIDCommServiceError> {
        Ok(parts.ctx.clone())
    }
}

impl FromMessageParts for Message {
    fn from_parts(parts: &mut MessageParts) -> Result<Self, DIDCommServiceError> {
        parts
            .message
            .take()
            .ok_or_else(|| DIDCommServiceError::Internal("Message already consumed".into()))
    }
}

impl FromMessageParts for UnpackMetadata {
    fn from_parts(parts: &mut MessageParts) -> Result<Self, DIDCommServiceError> {
        parts
            .meta
            .take()
            .ok_or_else(|| DIDCommServiceError::Internal("UnpackMetadata already consumed".into()))
    }
}

pub struct Extension<T>(pub T);

impl<T: Clone + Send + Sync + 'static> FromMessageParts for Extension<T> {
    fn from_parts(parts: &mut MessageParts) -> Result<Self, DIDCommServiceError> {
        parts
            .extensions
            .get::<T>()
            .cloned()
            .map(Extension)
            .ok_or_else(|| {
                DIDCommServiceError::Internal(format!(
                    "Extension not found: {}",
                    std::any::type_name::<T>()
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_insert_and_get() {
        let mut ext = Extensions::default();
        ext.insert(42u32);
        assert_eq!(ext.get::<u32>(), Some(&42));
    }

    #[test]
    fn extensions_get_returns_none_for_missing_type() {
        let ext = Extensions::default();
        assert!(ext.get::<String>().is_none());
    }

    #[test]
    fn extensions_overwrites_same_type() {
        let mut ext = Extensions::default();
        ext.insert("first".to_string());
        ext.insert("second".to_string());
        assert_eq!(ext.get::<String>(), Some(&"second".to_string()));
    }

    #[test]
    fn extensions_different_types_coexist() {
        let mut ext = Extensions::default();
        ext.insert(42u32);
        ext.insert("hello".to_string());
        assert_eq!(ext.get::<u32>(), Some(&42));
        assert_eq!(ext.get::<String>(), Some(&"hello".to_string()));
    }
}
