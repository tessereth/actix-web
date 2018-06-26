//! RequestState describes routing process state
use std::cell::RefCell;
use std::rc::Rc;

use info::ConnectionInfo;
use router::{Resource, Router};

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum RouterResource {
    Notset,
    Normal(u16),
}

/// RequestState describes routing process state
pub struct RequestState<S> {
    pub(crate) state: Rc<S>,
    pub(crate) router: Router,
    pub(crate) resource: RouterResource,
    pub(crate) info: RefCell<Option<ConnectionInfo>>,
    pub(crate) query: RefCell<Option<ConnectionInfo>>,
    pub(crate) cookies: RefCell<Option<ConnectionInfo>>,
}

impl<S> RequestState<S> {
    pub(crate) fn with_router(state: Rc<S>, router: Router) -> Self {
        RequestState {
            state,
            router,
            resource: RouterResource::Notset,
            info: RefCell::new(None),
            query: RefCell::new(None),
            cookies: RefCell::new(None),
        }
    }

    #[inline]
    /// Construct new http request with state.
    pub fn change_state<NS>(&self, state: Rc<NS>) -> RequestState<NS> {
        RequestState {
            state: state,
            router: self.router.clone(),
            resource: self.resource,
            info: RefCell::new(None),
            query: RefCell::new(None),
            cookies: RefCell::new(None),
        }
    }

    pub(crate) fn set_resource(&mut self, res: usize) {
        self.resource = RouterResource::Normal(res as u16);
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
}

impl<S> Clone for RequestState<S> {
    fn clone(&self) -> Self {
        RequestState {
            state: self.state.clone(),
            router: self.router.clone(),
            resource: self.resource,
            info: self.info.clone(),
            query: self.query.clone(),
            cookies: self.cookies.clone(),
        }
    }
}
