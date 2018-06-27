use std::cell::{Cell, Ref, RefCell, RefMut};
use std::collections::VecDeque;
use std::net::SocketAddr;

use http::{header, HeaderMap, Method, Uri, Version};

use extensions::Extensions;
use httpmessage::HttpMessage;
use info::ConnectionInfo;
use param::Params;
use payload::Payload;
use server::ServerSettings;
use uri::Url as InnerUrl;

bitflags! {
    pub(crate) struct MessageFlags: u8 {
        const KEEPALIVE = 0b0000_0001;
        const CONN_INFO = 0b0000_0010;
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
    pub(crate) flags: Cell<MessageFlags>,
    pub(crate) headers: HeaderMap,
    pub(crate) extensions: RefCell<Extensions>,
    pub(crate) params: Params,
    pub(crate) addr: Option<SocketAddr>,
    pub(crate) info: RefCell<ConnectionInfo>,
    pub(crate) payload: RefCell<Option<Payload>>,
    pub(crate) settings: ServerSettings,
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
    /// Create new RequestContext instance
    pub fn new(settings: ServerSettings) -> RequestContext {
        RequestContext {
            inner: Box::new(InnerRequestContext {
                settings,
                method: Method::GET,
                url: InnerUrl::default(),
                version: Version::HTTP_11,
                headers: HeaderMap::with_capacity(16),
                flags: Cell::new(MessageFlags::empty()),
                params: Params::new(),
                addr: None,
                info: RefCell::new(ConnectionInfo::default()),
                payload: RefCell::new(None),
                extensions: RefCell::new(Extensions::new()),
            }),
        }
    }

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

    /// Peer socket address
    ///
    /// Peer address is actual socket address, if proxy is used in front of
    /// actix http server, then peer address would be address of this proxy.
    ///
    /// To get client connection information `connection_info()` method should
    /// be used.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.addr
    }

    /// Checks if a connection should be kept alive.
    #[inline]
    pub fn keep_alive(&self) -> bool {
        self.inner.flags.get().contains(MessageFlags::KEEPALIVE)
    }

    /// Request extensions
    #[inline]
    pub fn extensions(&self) -> Ref<Extensions> {
        self.inner.extensions.borrow()
    }

    /// Mutable reference to a the request's extensions
    #[inline]
    pub fn extensions_mut(&self) -> RefMut<Extensions> {
        self.inner.extensions.borrow_mut()
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

    /// Get *ConnectionInfo* for the correct request.
    pub fn connection_info(&self) -> Ref<ConnectionInfo> {
        if self.inner.flags.get().contains(MessageFlags::CONN_INFO) {
            self.inner.info.borrow()
        } else {
            let mut flags = self.inner.flags.get();
            flags.insert(MessageFlags::CONN_INFO);
            self.inner.flags.set(flags);
            self.inner.info.borrow_mut().update(self);
            self.inner.info.borrow()
        }
    }

    /// Server settings
    #[inline]
    pub fn server_settings(&self) -> &ServerSettings {
        &self.inner.settings
    }

    #[inline]
    pub(crate) fn reset(&mut self) {
        self.inner.headers.clear();
        self.inner.extensions.borrow_mut().clear();
        self.inner.params.clear();
        self.inner.flags.set(MessageFlags::empty());
        *self.inner.payload.borrow_mut() = None;
    }
}

pub(crate) struct RequestContextPool(
    RefCell<VecDeque<RequestContext>>,
    RefCell<ServerSettings>,
);

thread_local!(static POOL: &'static RequestContextPool = RequestContextPool::create());

impl RequestContextPool {
    fn create() -> &'static RequestContextPool {
        let pool = RequestContextPool(
            RefCell::new(VecDeque::with_capacity(128)),
            RefCell::new(ServerSettings::default()),
        );
        Box::leak(Box::new(pool))
    }

    pub fn pool(settings: ServerSettings) -> &'static RequestContextPool {
        POOL.with(|p| {
            *p.1.borrow_mut() = settings;
            *p
        })
    }

    #[inline]
    pub fn get(&self) -> RequestContext {
        if let Some(msg) = self.0.borrow_mut().pop_front() {
            msg
        } else {
            RequestContext::new(self.1.borrow().clone())
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
