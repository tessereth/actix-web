use std::net::SocketAddr;

use http::{HeaderMap, Method, Version};

use extensions::Extensions;
use param::Params;
use payload::Payload;
use uri::Url as InnerUrl;

bitflags! {
    pub(crate) struct MessageFlags: u8 {
        const KEEPALIVE = 0b0000_0010;
    }
}

/// Request's context
pub struct HttpRequestContext {
    pub(crate) version: Version,
    pub(crate) method: Method,
    pub(crate) url: InnerUrl,
    pub(crate) flags: MessageFlags,
    pub(crate) headers: HeaderMap,
    pub(crate) extensions: Extensions,
    pub(crate) params: Params,
    pub(crate) addr: Option<SocketAddr>,
    pub(crate) payload: Option<Payload>,
    pub(crate) prefix: u16,
}

impl Default for HttpRequestContext {
    fn default() -> HttpRequestContext {
        HttpRequestContext {
            method: Method::GET,
            url: InnerUrl::default(),
            version: Version::HTTP_11,
            headers: HeaderMap::with_capacity(16),
            flags: MessageFlags::empty(),
            params: Params::new(),
            addr: None,
            payload: None,
            extensions: Extensions::new(),
            prefix: 0,
        }
    }
}

impl HttpRequestContext {
    /// Checks if a connection should be kept alive.
    #[inline]
    pub fn keep_alive(&self) -> bool {
        self.flags.contains(MessageFlags::KEEPALIVE)
    }

    #[inline]
    /// Returns Request's headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    #[inline]
    /// Returns mutable Request's headers.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Request extensions
    #[inline]
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Mutable reference to a the request's extensions
    #[inline]
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    #[inline]
    pub(crate) fn reset(&mut self) {
        self.headers.clear();
        self.extensions.clear();
        self.params.clear();
        self.addr = None;
        self.flags = MessageFlags::empty();
        self.payload = None;
        self.prefix = 0;
    }
}
