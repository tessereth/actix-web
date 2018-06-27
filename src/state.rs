//! RequestContext describes routing process state
use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use info::ConnectionInfo;
use router::{Resource, Router};
use server::Request;

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum RouterResource {
    Notset,
    Normal(u16),
}

/// RequestContext describes routing process state
pub struct RequestContext<S> {
    pub(crate) req: Option<Request>,
    pub(crate) state: Rc<S>,
    pub(crate) router: Router,
    pub(crate) resource: RouterResource,
    pub(crate) info: RefCell<Option<ConnectionInfo>>,
    pub(crate) query: RefCell<Option<ConnectionInfo>>,
    pub(crate) cookies: RefCell<Option<ConnectionInfo>>,
    pub(crate) prefix: u16,
}

impl<S> Deref for RequestContext<S> {
    type Target = Request;

    fn deref(&self) -> &Request {
        self.req.as_ref().unwrap()
    }
}

impl<S> DerefMut for RequestContext<S> {
    fn deref_mut(&mut self) -> &mut Request {
        self.req.as_mut().unwrap()
    }
}

impl<S> RequestContext<S> {
    pub(crate) fn new(req: Request, state: Rc<S>, router: Router) -> Self {
        RequestContext {
            req: Some(req),
            state,
            router,
            resource: RouterResource::Notset,
            info: RefCell::new(None),
            query: RefCell::new(None),
            cookies: RefCell::new(None),
            prefix: 0,
        }
    }

    #[inline]
    /// Construct new http request with state.
    pub fn change_state<NS>(self, state: Rc<NS>) -> RequestContext<NS> {
        RequestContext {
            state,
            req: self.req,
            router: self.router.clone(),
            resource: self.resource,
            prefix: self.prefix,
            info: RefCell::new(None),
            query: RefCell::new(None),
            cookies: RefCell::new(None),
        }
    }

    pub(crate) fn set_resource(&mut self, res: usize) {
        self.resource = RouterResource::Normal(res as u16);
    }

    /// Current `Request`
    #[inline]
    pub fn request(&self) -> &Request {
        self.req.as_ref().unwrap()
    }

    /// Current `Request`
    #[inline]
    pub fn request_mut(&mut self) -> &mut Request {
        self.req.as_mut().unwrap()
    }

    /// This method returns reference to current `Router` object.
    #[inline]
    pub fn router(&self) -> &Router {
        &self.router
    }

    /// This method returns reference to matched `Resource` object.
    #[inline]
    pub fn resource(&self) -> Option<&Resource> {
        if let RouterResource::Normal(idx) = self.resource {
            return Some(self.router.get_resource(idx as usize));
        }
        None
    }

    #[doc(hidden)]
    pub fn prefix_len(&self) -> u16 {
        self.prefix as u16
    }

    #[doc(hidden)]
    pub fn set_prefix_len(&mut self, len: u16) {
        self.prefix = len;
    }

    pub(crate) fn set_prefix_and_resource(&mut self, len: u16, res: usize) {
        self.prefix = len;
        self.resource = RouterResource::Normal(res as u16);
    }
}
