use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::SocketAddr;

use http::{header, HeaderMap, Method, Uri, Version};

use extensions::Extensions;
use httpmessage::HttpMessage;
use param::Params;
use payload::Payload;
use uri::Url as InnerUrl;

bitflags! {
    pub(crate) struct MessageFlags: u8 {
        const KEEPALIVE = 0b0000_0010;
    }
}

/// Request's context
pub struct RequestContext {
    pub(crate) inner: Box<InnerRequestContext>,
}

pub(crate) struct InnerRequestContext {
    pub(crate) version: Version,
    pub(crate) method: Method,
    pub(crate) url: InnerUrl,
    pub(crate) flags: MessageFlags,
    pub(crate) headers: HeaderMap,
    pub(crate) extensions: Extensions,
    pub(crate) params: Params,
    pub(crate) addr: Option<SocketAddr>,
    pub(crate) payload: RefCell<Option<Payload>>,
    pub(crate) prefix: u16,
}

impl Default for RequestContext {
    fn default() -> RequestContext {
        RequestContext {
            inner: Box::new(InnerRequestContext {
                method: Method::GET,
                url: InnerUrl::default(),
                version: Version::HTTP_11,
                headers: HeaderMap::with_capacity(16),
                flags: MessageFlags::empty(),
                params: Params::new(),
                addr: None,
                payload: RefCell::new(None),
                extensions: Extensions::new(),
                prefix: 0,
            }),
        }
    }
}

impl HttpMessage for RequestContext {
    type Stream = Payload;

    fn headers(&self) -> &HeaderMap {
        &self.inner.headers
    }

    #[inline]
    fn payload(&self) -> Payload {
        if let Some(payload) = self.inner.payload.borrow_mut().take() {
            payload
        } else {
            Payload::empty()
        }
    }
}

impl RequestContext {
    #[inline]
    pub(crate) fn url(&self) -> &InnerUrl {
        &self.inner.url
    }

    /// Read the Request Uri.
    #[inline]
    pub fn uri(&self) -> &Uri {
        self.inner.url.uri()
    }

    /// Read the Request method.
    #[inline]
    pub fn method(&self) -> &Method {
        &self.inner.method
    }

    /// Read the Request Version.
    #[inline]
    pub fn version(&self) -> Version {
        self.inner.version
    }

    /// The target path of this Request.
    #[inline]
    pub fn path(&self) -> &str {
        self.inner.url.path()
    }

    #[inline]
    /// Returns Request's headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.inner.headers
    }

    #[inline]
    /// Returns mutable Request's headers.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.inner.headers
    }

    /// Checks if a connection should be kept alive.
    #[inline]
    pub fn keep_alive(&self) -> bool {
        self.inner.flags.contains(MessageFlags::KEEPALIVE)
    }

    /// Request extensions
    #[inline]
    pub fn extensions(&self) -> &Extensions {
        &self.inner.extensions
    }

    /// Mutable reference to a the request's extensions
    #[inline]
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.inner.extensions
    }

    /// Get a reference to the Params object.
    ///
    /// Params is a container for url parameters.
    /// A variable segment is specified in the form `{identifier}`,
    /// where the identifier can be used later in a request handler to
    /// access the matched value for that segment.
    #[inline]
    pub fn match_info(&self) -> &Params {
        &self.inner.params
    }

    /// Get mutable reference to request's Params.
    #[inline]
    pub fn match_info_mut(&mut self) -> &mut Params {
        &mut self.inner.params
    }

    /// Check if request requires connection upgrade
    pub fn upgrade(&self) -> bool {
        if let Some(conn) = self.inner.headers.get(header::CONNECTION) {
            if let Ok(s) = conn.to_str() {
                return s.to_lowercase().contains("upgrade");
            }
        }
        self.inner.method == Method::CONNECT
    }

    #[doc(hidden)]
    pub fn prefix_len(&self) -> u16 {
        self.inner.prefix as u16
    }

    #[doc(hidden)]
    pub fn set_prefix_len(&mut self, len: u16) {
        self.inner.prefix = len;
    }

    #[inline]
    pub(crate) fn reset(&mut self) {
        self.inner.headers.clear();
        self.inner.extensions.clear();
        self.inner.params.clear();
        self.inner.flags = MessageFlags::empty();
        //*self.inner.payload.borrow_mut() = None;
        self.inner.prefix = 0;
    }
}

pub(crate) struct RequestContextPool(RefCell<VecDeque<RequestContext>>);

thread_local!(static POOL: &'static RequestContextPool = RequestContextPool::create());

impl RequestContextPool {
    fn create() -> &'static RequestContextPool {
        let pool = RequestContextPool(RefCell::new(VecDeque::with_capacity(128)));
        Box::leak(Box::new(pool))
    }

    pub fn pool() -> &'static RequestContextPool {
        POOL.with(|p| *p)
    }

    #[inline]
    pub fn get(&self) -> RequestContext {
        if let Some(msg) = self.0.borrow_mut().pop_front() {
            msg
        } else {
            RequestContext::default()
        }
    }

    #[inline]
    pub fn release(&self, mut msg: RequestContext) {
        let v = &mut self.0.borrow_mut();
        if v.len() < 128 {
            msg.reset();
            v.push_front(msg);
        }
    }
}
