use std::marker::PhantomData;
use std::mem;
use std::rc::Rc;

use futures::{Async, Future, Poll};

use error::Error;
use handler::{
    AsyncResult, AsyncResultItem, FromRequest, Responder, RouteHandler, RouteResult,
};
use http::{Method, StatusCode};
use httprequest::HttpRequest;
use httpresponse::HttpResponse;
use middleware::{
    Finished as MiddlewareFinished, Middleware, Response as MiddlewareResponse,
    Started as MiddlewareStarted,
};
use pred::Predicate;
use resource::{ResourceHandler, RouteId};
use router::Resource;
use server::RequestContext;
use state::RequestState;

type ScopeResource<S> = Rc<ResourceHandler<S>>;
type Route<S> = Box<RouteHandler<S>>;
type ScopeResources<S> = Rc<Vec<(Resource, ScopeResource<S>)>>;
type NestedInfo<S> = (Resource, Route<S>, Vec<Box<Predicate<S>>>);

/// Resources scope
///
/// Scope is a set of resources with common root path.
/// Scopes collect multiple paths under a common path prefix.
/// Scope path can contain variable path segments as resources.
/// Scope prefix is always complete path segment, i.e `/app` would
/// be converted to a `/app/` and it would not match `/app` path.
///
/// You can get variable path segments from `HttpRequest::match_info()`.
/// `Path` extractor also is able to extract scope level variable segments.
///
/// ```rust
/// # extern crate actix_web;
/// use actix_web::{http, App, HttpRequest, HttpResponse};
///
/// fn main() {
///     let app = App::new().scope("/{project_id}/", |scope| {
///         scope
///             .resource("/path1", |r| r.f(|_| HttpResponse::Ok()))
///             .resource("/path2", |r| r.f(|_| HttpResponse::Ok()))
///             .resource("/path3", |r| r.f(|_| HttpResponse::MethodNotAllowed()))
///     });
/// }
/// ```
///
/// In the above example three routes get registered:
///  * /{project_id}/path1 - reponds to all http method
///  * /{project_id}/path2 - `GET` requests
///  * /{project_id}/path3 - `HEAD` requests
///
#[derive(Default)]
pub struct Scope<S: 'static> {
    filters: Vec<Box<Predicate<S>>>,
    nested: Vec<NestedInfo<S>>,
    middlewares: Rc<Vec<Box<Middleware<S>>>>,
    default: Option<ScopeResource<S>>,
    resources: ScopeResources<S>,
}

#[cfg_attr(feature = "cargo-clippy", allow(new_without_default_derive))]
impl<S: 'static> Scope<S> {
    /// Create a new scope
    // TODO: Why is this not exactly the default impl?
    pub fn new() -> Scope<S> {
        Scope {
            filters: Vec::new(),
            nested: Vec::new(),
            resources: Rc::new(Vec::new()),
            middlewares: Rc::new(Vec::new()),
            default: None,
        }
    }

    #[inline]
    pub(crate) fn take_filters(&mut self) -> Vec<Box<Predicate<S>>> {
        mem::replace(&mut self.filters, Vec::new())
    }

    /// Add match predicate to scope.
    ///
    /// ```rust
    /// # extern crate actix_web;
    /// use actix_web::{http, pred, App, HttpRequest, HttpResponse, Path};
    ///
    /// fn index(data: Path<(String, String)>) -> &'static str {
    ///     "Welcome!"
    /// }
    ///
    /// fn main() {
    ///     let app = App::new().scope("/app", |scope| {
    ///         scope
    ///             .filter(pred::Header("content-type", "text/plain"))
    ///             .route("/test1", http::Method::GET, index)
    ///             .route("/test2", http::Method::POST, |_: HttpRequest| {
    ///                 HttpResponse::MethodNotAllowed()
    ///             })
    ///     });
    /// }
    /// ```
    pub fn filter<T: Predicate<S> + 'static>(mut self, p: T) -> Self {
        self.filters.push(Box::new(p));
        self
    }

    /// Create nested scope with new state.
    ///
    /// ```rust
    /// # extern crate actix_web;
    /// use actix_web::{App, HttpRequest};
    ///
    /// struct AppState;
    ///
    /// fn index(req: HttpRequest<AppState>) -> &'static str {
    ///     "Welcome!"
    /// }
    ///
    /// fn main() {
    ///     let app = App::new().scope("/app", |scope| {
    ///         scope.with_state("/state2", AppState, |scope| {
    ///             scope.resource("/test1", |r| r.f(index))
    ///         })
    ///     });
    /// }
    /// ```
    pub fn with_state<F, T: 'static>(mut self, path: &str, state: T, f: F) -> Scope<S>
    where
        F: FnOnce(Scope<T>) -> Scope<T>,
    {
        let scope = Scope {
            filters: Vec::new(),
            nested: Vec::new(),
            resources: Rc::new(Vec::new()),
            middlewares: Rc::new(Vec::new()),
            default: None,
        };
        let mut scope = f(scope);

        let state = Rc::new(state);
        let filters: Vec<Box<Predicate<S>>> = vec![Box::new(FiltersWrapper {
            state: Rc::clone(&state),
            filters: scope.take_filters(),
        })];
        let handler = Box::new(Wrapper { scope, state });
        self.nested
            .push((Resource::prefix("", &path), handler, filters));

        self
    }

    /// Create nested scope.
    ///
    /// ```rust
    /// # extern crate actix_web;
    /// use actix_web::{App, HttpRequest};
    ///
    /// struct AppState;
    ///
    /// fn index(req: HttpRequest<AppState>) -> &'static str {
    ///     "Welcome!"
    /// }
    ///
    /// fn main() {
    ///     let app = App::with_state(AppState).scope("/app", |scope| {
    ///         scope.nested("/v1", |scope| scope.resource("/test1", |r| r.f(index)))
    ///     });
    /// }
    /// ```
    pub fn nested<F>(mut self, path: &str, f: F) -> Scope<S>
    where
        F: FnOnce(Scope<S>) -> Scope<S>,
    {
        let scope = Scope {
            filters: Vec::new(),
            nested: Vec::new(),
            resources: Rc::new(Vec::new()),
            middlewares: Rc::new(Vec::new()),
            default: None,
        };
        let mut scope = f(scope);

        let filters = scope.take_filters();
        self.nested
            .push((Resource::prefix("", &path), Box::new(scope), filters));

        self
    }

    /// Configure route for a specific path.
    ///
    /// This is a simplified version of the `Scope::resource()` method.
    /// Handler functions need to accept one request extractor
    /// argument.
    ///
    /// This method could be called multiple times, in that case
    /// multiple routes would be registered for same resource path.
    ///
    /// ```rust
    /// # extern crate actix_web;
    /// use actix_web::{http, App, HttpRequest, HttpResponse, Path};
    ///
    /// fn index(data: Path<(String, String)>) -> &'static str {
    ///     "Welcome!"
    /// }
    ///
    /// fn main() {
    ///     let app = App::new().scope("/app", |scope| {
    ///         scope.route("/test1", http::Method::GET, index).route(
    ///             "/test2",
    ///             http::Method::POST,
    ///             |_: HttpRequest| HttpResponse::MethodNotAllowed(),
    ///         )
    ///     });
    /// }
    /// ```
    pub fn route<T, F, R>(mut self, path: &str, method: Method, f: F) -> Scope<S>
    where
        F: Fn(T) -> R + 'static,
        R: Responder + 'static,
        T: FromRequest<S> + 'static,
    {
        // check if we have resource handler
        let mut found = false;
        for &(ref pattern, _) in self.resources.iter() {
            if pattern.pattern() == path {
                found = true;
                break;
            }
        }

        if found {
            let resources = Rc::get_mut(&mut self.resources)
                .expect("Multiple scope references are not allowed");
            for &mut (ref pattern, ref mut resource) in resources.iter_mut() {
                if pattern.pattern() == path {
                    let res = Rc::get_mut(resource)
                        .expect("Multiple scope references are not allowed");
                    res.method(method).with(f);
                    break;
                }
            }
        } else {
            let mut handler = ResourceHandler::default();
            handler.method(method).with(f);
            let pattern = Resource::with_prefix(
                handler.get_name(),
                path,
                if path.is_empty() { "" } else { "/" },
                false,
            );
            Rc::get_mut(&mut self.resources)
                .expect("Can not use after configuration")
                .push((pattern, Rc::new(handler)));
        }
        self
    }

    /// Configure resource for a specific path.
    ///
    /// This method is similar to an `App::resource()` method.
    /// Resources may have variable path segments. Resource path uses scope
    /// path as a path prefix.
    ///
    /// ```rust
    /// # extern crate actix_web;
    /// use actix_web::*;
    ///
    /// fn main() {
    ///     let app = App::new().scope("/api", |scope| {
    ///         scope.resource("/users/{userid}/{friend}", |r| {
    ///             r.get().f(|_| HttpResponse::Ok());
    ///             r.head().f(|_| HttpResponse::MethodNotAllowed());
    ///             r.route()
    ///                 .filter(pred::Any(pred::Get()).or(pred::Put()))
    ///                 .filter(pred::Header("Content-Type", "text/plain"))
    ///                 .f(|_| HttpResponse::Ok())
    ///         })
    ///     });
    /// }
    /// ```
    pub fn resource<F, R>(mut self, path: &str, f: F) -> Scope<S>
    where
        F: FnOnce(&mut ResourceHandler<S>) -> R + 'static,
    {
        // add resource handler
        let mut handler = ResourceHandler::default();
        f(&mut handler);

        let pattern = Resource::with_prefix(
            handler.get_name(),
            path,
            if path.is_empty() { "" } else { "/" },
            false,
        );
        Rc::get_mut(&mut self.resources)
            .expect("Can not use after configuration")
            .push((pattern, Rc::new(handler)));

        self
    }

    /// Default resource to be used if no matching route could be found.
    pub fn default_resource<F, R>(mut self, f: F) -> Scope<S>
    where
        F: FnOnce(&mut ResourceHandler<S>) -> R + 'static,
    {
        if self.default.is_none() {
            self.default = Some(Rc::new(ResourceHandler::default_not_found()));
        }
        {
            let default = Rc::get_mut(self.default.as_mut().unwrap())
                .expect("Multiple copies of default handler");
            f(default);
        }
        self
    }

    /// Register a scope middleware
    ///
    /// This is similar to `App's` middlewares, but
    /// middlewares get invoked on scope level.
    ///
    /// *Note* `Middleware::finish()` fires right after response get
    /// prepared. It does not wait until body get sent to the peer.
    pub fn middleware<M: Middleware<S>>(mut self, mw: M) -> Scope<S> {
        Rc::get_mut(&mut self.middlewares)
            .expect("Can not use after configuration")
            .push(Box::new(mw));
        self
    }
}

impl<S: 'static> RouteHandler<S> for Scope<S> {
    fn handle(
        &self, mut msg: RequestContext, mut state: RequestState<S>,
    ) -> RouteResult<S> {
        let tail = msg.match_info().tail as usize;

        // recognize resources
        for &(ref pattern, ref resource) in self.resources.iter() {
            if pattern.match_with_params(&mut msg, tail, false) {
                if let Some(id) = resource.get_route_id(&mut msg, &state) {
                    if self.middlewares.is_empty() {
                        return resource.handle(id, msg, state);
                    } else {
                        return AsyncResult::async(Box::new(Compose::new(
                            id,
                            msg,
                            state,
                            Rc::clone(&self.middlewares),
                            Rc::clone(&resource),
                        )));
                    }
                }
            }
        }

        // nested scopes
        let len = state.prefix_len() as usize;
        'outer: for &(ref prefix, ref handler, ref filters) in &self.nested {
            if let Some(prefix_len) = prefix.match_prefix_with_params(&mut msg, len) {
                for filter in filters {
                    if !filter.check(&mut msg, state.state.as_ref()) {
                        continue 'outer;
                    }
                }
                let url = msg.url().clone();
                let prefix_len = (len + prefix_len) as u16;
                state.set_prefix_len(prefix_len);
                msg.match_info_mut().set_tail(prefix_len);
                msg.match_info_mut().set_url(url);
                return handler.handle(msg, state);
            }
        }

        // default handler
        if let Some(ref resource) = self.default {
            if let Some(id) = resource.get_route_id(&mut msg, &state) {
                if self.middlewares.is_empty() {
                    return resource.handle(id, msg, state);
                } else {
                    return AsyncResult::async(Box::new(Compose::new(
                        id,
                        msg,
                        state,
                        Rc::clone(&self.middlewares),
                        Rc::clone(resource),
                    )));
                }
            }
        }

        let req = HttpRequest::from_state(msg, state);
        AsyncResult::ok((req, HttpResponse::new(StatusCode::NOT_FOUND)))
    }

    fn has_default_resource(&self) -> bool {
        self.default.is_some()
    }

    fn default_resource(&mut self, default: ScopeResource<S>) {
        self.default = Some(default);
    }
}

struct Wrapper<S: 'static> {
    state: Rc<S>,
    scope: Scope<S>,
}

impl<S: 'static, S2: 'static> RouteHandler<S2> for Wrapper<S> {
    fn handle(&self, msg: RequestContext, state: RequestState<S2>) -> RouteResult<S2> {
        //let (result, req) = self
        //    .scope
        //    .handle(msg, state.change_state(Rc::clone(&self.state)));
        //(result, req.change_state())
        unimplemented!()
    }
}

struct FiltersWrapper<S: 'static> {
    state: Rc<S>,
    filters: Vec<Box<Predicate<S>>>,
}

impl<S: 'static, S2: 'static> Predicate<S2> for FiltersWrapper<S> {
    fn check(&self, msg: &mut RequestContext, _: &S2) -> bool {
        for filter in &self.filters {
            if !filter.check(msg, &self.state) {
                return false;
            }
        }
        true
    }
}

/// Compose resource level middlewares with route handler.
struct Compose<S: 'static> {
    info: ComposeInfo<S>,
    state: ComposeState<S>,
}

struct ComposeInfo<S: 'static> {
    count: usize,
    id: RouteId,
    ctx: Option<(RequestContext, RequestState<S>)>,
    req: Option<HttpRequest<S>>,
    mws: Rc<Vec<Box<Middleware<S>>>>,
    resource: Rc<ResourceHandler<S>>,
}

enum ComposeState<S: 'static> {
    Starting(StartMiddlewares<S>),
    Handler(WaitingResponse<S>),
    RunMiddlewares(RunMiddlewares<S>),
    Finishing(FinishingMiddlewares<S>),
    Completed(Response<S>),
}

impl<S: 'static> ComposeState<S> {
    fn poll(&mut self, info: &mut ComposeInfo<S>) -> Option<ComposeState<S>> {
        match *self {
            ComposeState::Starting(ref mut state) => state.poll(info),
            ComposeState::Handler(ref mut state) => state.poll(info),
            ComposeState::RunMiddlewares(ref mut state) => state.poll(info),
            ComposeState::Finishing(ref mut state) => state.poll(info),
            ComposeState::Completed(_) => None,
        }
    }
}

impl<S: 'static> Compose<S> {
    fn new(
        id: RouteId, msg: RequestContext, state: RequestState<S>,
        mws: Rc<Vec<Box<Middleware<S>>>>, resource: Rc<ResourceHandler<S>>,
    ) -> Self {
        let mut info = ComposeInfo {
            id,
            mws,
            resource,
            count: 0,
            req: None,
            ctx: Some((msg, state)),
        };
        let state = StartMiddlewares::init(&mut info);

        Compose { state, info }
    }
}

impl<S> Future for Compose<S> {
    type Item = (HttpRequest<S>, HttpResponse);
    type Error = (HttpRequest<S>, Error);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if let ComposeState::Completed(ref mut resp) = self.state {
                let req = self.info.req.take().unwrap();
                let resp = resp.resp.take().unwrap();
                return Ok(Async::Ready((req, resp)));
            }
            if let Some(state) = self.state.poll(&mut self.info) {
                self.state = state;
            } else {
                return Ok(Async::NotReady);
            }
        }
    }
}

/// Middlewares start executor
struct StartMiddlewares<S> {
    fut: Option<Fut>,
    _s: PhantomData<S>,
}

type Fut = Box<Future<Item = Option<HttpResponse>, Error = Error>>;

impl<S: 'static> StartMiddlewares<S> {
    fn init(info: &mut ComposeInfo<S>) -> ComposeState<S> {
        let len = info.mws.len();
        let (mut ctx, state) = info.ctx.take().unwrap();

        loop {
            if info.count == len {
                let reply = info.resource.handle(info.id, ctx, state);
                return WaitingResponse::init(info, reply);
            } else {
                let result = info.mws[info.count].start(&mut ctx, &state);
                match result {
                    Ok(MiddlewareStarted::Done) => info.count += 1,
                    Ok(MiddlewareStarted::Response(resp)) => {
                        let req = HttpRequest::from_state(ctx, state);
                        return RunMiddlewares::init(info, req, resp);
                    }
                    Ok(MiddlewareStarted::Future(fut)) => {
                        info.ctx = Some((ctx, state));
                        return ComposeState::Starting(StartMiddlewares {
                            fut: Some(fut),
                            _s: PhantomData,
                        });
                    }
                    Err(err) => {
                        let req = HttpRequest::from_state(ctx, state);
                        return RunMiddlewares::init(info, req, err.into());
                    }
                }
            }
        }
    }

    fn poll(&mut self, info: &mut ComposeInfo<S>) -> Option<ComposeState<S>> {
        let len = info.mws.len();
        let (mut ctx, state) = info.ctx.take().unwrap();

        'outer: loop {
            match self.fut.as_mut().unwrap().poll() {
                Ok(Async::NotReady) => {
                    info.ctx = Some((ctx, state));
                    return None;
                }
                Ok(Async::Ready(resp)) => {
                    info.count += 1;

                    if let Some(resp) = resp {
                        let req = HttpRequest::from_state(ctx, state);
                        return Some(RunMiddlewares::init(info, req, resp));
                    }
                    loop {
                        if info.count == len {
                            let reply = { info.resource.handle(info.id, ctx, state) };
                            return Some(WaitingResponse::init(info, reply));
                        } else {
                            let result = info.mws[info.count].start(&mut ctx, &state);
                            match result {
                                Ok(MiddlewareStarted::Done) => info.count += 1,
                                Ok(MiddlewareStarted::Response(resp)) => {
                                    let req = HttpRequest::from_state(ctx, state);
                                    return Some(RunMiddlewares::init(info, req, resp));
                                }
                                Ok(MiddlewareStarted::Future(fut)) => {
                                    self.fut = Some(fut);
                                    continue 'outer;
                                }
                                Err(err) => {
                                    let req = HttpRequest::from_state(ctx, state);
                                    return Some(RunMiddlewares::init(
                                        info,
                                        req,
                                        err.into(),
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    let req = HttpRequest::from_state(ctx, state);
                    return Some(RunMiddlewares::init(info, req, err.into()));
                }
            }
        }
    }
}

type HandlerFuture<S> =
    Future<Item = (HttpRequest<S>, HttpResponse), Error = (HttpRequest<S>, Error)>;

// waiting for response
struct WaitingResponse<S> {
    fut: Box<HandlerFuture<S>>,
    _s: PhantomData<S>,
}

impl<S: 'static> WaitingResponse<S> {
    #[inline]
    fn init(info: &mut ComposeInfo<S>, reply: RouteResult<S>) -> ComposeState<S> {
        match reply.into() {
            AsyncResultItem::Ok((req, resp)) => RunMiddlewares::init(info, req, resp),
            AsyncResultItem::Err((req, err)) => {
                RunMiddlewares::init(info, req, err.into())
            }
            AsyncResultItem::Future(fut) => ComposeState::Handler(WaitingResponse {
                fut,
                _s: PhantomData,
            }),
        }
    }

    fn poll(&mut self, info: &mut ComposeInfo<S>) -> Option<ComposeState<S>> {
        match self.fut.poll() {
            Ok(Async::NotReady) => None,
            Ok(Async::Ready((req, resp))) => Some(RunMiddlewares::init(info, req, resp)),
            Err((req, err)) => Some(RunMiddlewares::init(info, req, err.into())),
        }
    }
}

/// Middlewares response executor
struct RunMiddlewares<S> {
    curr: usize,
    fut: Option<Box<Future<Item = HttpResponse, Error = Error>>>,
    _s: PhantomData<S>,
}

impl<S: 'static> RunMiddlewares<S> {
    fn init(
        info: &mut ComposeInfo<S>, mut req: HttpRequest<S>, mut resp: HttpResponse,
    ) -> ComposeState<S> {
        let mut curr = 0;
        let len = info.mws.len();

        loop {
            let state = info.mws[curr].response(&mut req, resp);
            resp = match state {
                Err(err) => {
                    info.req = Some(req);
                    info.count = curr + 1;
                    return FinishingMiddlewares::init(info, err.into());
                }
                Ok(MiddlewareResponse::Done(r)) => {
                    curr += 1;
                    if curr == len {
                        info.req = Some(req);
                        return FinishingMiddlewares::init(info, r);
                    } else {
                        r
                    }
                }
                Ok(MiddlewareResponse::Future(fut)) => {
                    info.req = Some(req);
                    return ComposeState::RunMiddlewares(RunMiddlewares {
                        curr,
                        fut: Some(fut),
                        _s: PhantomData,
                    });
                }
            };
        }
    }

    fn poll(&mut self, info: &mut ComposeInfo<S>) -> Option<ComposeState<S>> {
        let len = info.mws.len();

        loop {
            // poll latest fut
            let mut resp = match self.fut.as_mut().unwrap().poll() {
                Ok(Async::NotReady) => return None,
                Ok(Async::Ready(resp)) => {
                    self.curr += 1;
                    resp
                }
                Err(err) => return Some(FinishingMiddlewares::init(info, err.into())),
            };

            loop {
                if self.curr == len {
                    return Some(FinishingMiddlewares::init(info, resp));
                } else {
                    let state =
                        info.mws[self.curr].response(info.req.as_mut().unwrap(), resp);
                    match state {
                        Err(err) => {
                            return Some(FinishingMiddlewares::init(info, err.into()))
                        }
                        Ok(MiddlewareResponse::Done(r)) => {
                            self.curr += 1;
                            resp = r
                        }
                        Ok(MiddlewareResponse::Future(fut)) => {
                            self.fut = Some(fut);
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Middlewares start executor
struct FinishingMiddlewares<S> {
    resp: Option<HttpResponse>,
    fut: Option<Box<Future<Item = (), Error = Error>>>,
    _s: PhantomData<S>,
}

impl<S: 'static> FinishingMiddlewares<S> {
    fn init(info: &mut ComposeInfo<S>, resp: HttpResponse) -> ComposeState<S> {
        if info.count == 0 {
            Response::init(resp)
        } else {
            let mut state = FinishingMiddlewares {
                resp: Some(resp),
                fut: None,
                _s: PhantomData,
            };
            if let Some(st) = state.poll(info) {
                st
            } else {
                ComposeState::Finishing(state)
            }
        }
    }

    fn poll(&mut self, info: &mut ComposeInfo<S>) -> Option<ComposeState<S>> {
        loop {
            // poll latest fut
            let not_ready = if let Some(ref mut fut) = self.fut {
                match fut.poll() {
                    Ok(Async::NotReady) => true,
                    Ok(Async::Ready(())) => false,
                    Err(err) => {
                        error!("Middleware finish error: {}", err);
                        false
                    }
                }
            } else {
                false
            };
            if not_ready {
                return None;
            }
            self.fut = None;
            if info.count == 0 {
                return Some(Response::init(self.resp.take().unwrap()));
            }

            info.count -= 1;
            let state = info.mws[info.count as usize]
                .finish(info.req.as_mut().unwrap(), self.resp.as_ref().unwrap());
            match state {
                MiddlewareFinished::Done => {
                    if info.count == 0 {
                        return Some(Response::init(self.resp.take().unwrap()));
                    }
                }
                MiddlewareFinished::Future(fut) => {
                    self.fut = Some(fut);
                }
            }
        }
    }
}

struct Response<S> {
    resp: Option<HttpResponse>,
    _s: PhantomData<S>,
}

impl<S: 'static> Response<S> {
    fn init(resp: HttpResponse) -> ComposeState<S> {
        ComposeState::Completed(Response {
            resp: Some(resp),
            _s: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use application::App;
    use body::Body;
    use http::{Method, StatusCode};
    use httprequest::HttpRequest;
    use httpresponse::HttpResponse;
    use pred;
    use test::TestRequest;

    #[test]
    fn test_scope() {
        let app = App::new()
            .scope("/app", |scope| {
                scope.resource("/path1", |r| r.f(|_| HttpResponse::Ok()))
            })
            .finish();

        let req = TestRequest::with_uri("/app/path1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);
    }

    #[test]
    fn test_scope_root() {
        let app = App::new()
            .scope("/app", |scope| {
                scope
                    .resource("", |r| r.f(|_| HttpResponse::Ok()))
                    .resource("/", |r| r.f(|_| HttpResponse::Created()))
            })
            .finish();

        let req = TestRequest::with_uri("/app").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);

        let req = TestRequest::with_uri("/app/").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::CREATED);
    }

    #[test]
    fn test_scope_root2() {
        let app = App::new()
            .scope("/app/", |scope| {
                scope.resource("", |r| r.f(|_| HttpResponse::Ok()))
            })
            .finish();

        let req = TestRequest::with_uri("/app").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/app/").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);
    }

    #[test]
    fn test_scope_root3() {
        let app = App::new()
            .scope("/app/", |scope| {
                scope.resource("/", |r| r.f(|_| HttpResponse::Ok()))
            })
            .finish();

        let req = TestRequest::with_uri("/app").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/app/").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_scope_route() {
        let app = App::new()
            .scope("app", |scope| {
                scope
                    .route("/path1", Method::GET, |_: HttpRequest<_>| {
                        HttpResponse::Ok()
                    })
                    .route("/path1", Method::DELETE, |_: HttpRequest<_>| {
                        HttpResponse::Ok()
                    })
            })
            .finish();

        let req = TestRequest::with_uri("/app/path1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);

        let req = TestRequest::with_uri("/app/path1")
            .method(Method::DELETE)
            .context()
            .0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);

        let req = TestRequest::with_uri("/app/path1")
            .method(Method::POST)
            .context()
            .0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_scope_filter() {
        let app = App::new()
            .scope("/app", |scope| {
                scope
                    .filter(pred::Get())
                    .resource("/path1", |r| r.f(|_| HttpResponse::Ok()))
            })
            .finish();

        let req = TestRequest::with_uri("/app/path1")
            .method(Method::POST)
            .context()
            .0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/app/path1")
            .method(Method::GET)
            .context()
            .0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);
    }

    #[test]
    fn test_scope_variable_segment() {
        let app = App::new()
            .scope("/ab-{project}", |scope| {
                scope.resource("/path1", |r| {
                    r.f(|r| {
                        HttpResponse::Ok()
                            .body(format!("project: {}", &r.match_info()["project"]))
                    })
                })
            })
            .finish();

        let req = TestRequest::with_uri("/ab-project1/path1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);

        match resp.as_msg().1.body() {
            &Body::Binary(ref b) => {
                let bytes: Bytes = b.clone().into();
                assert_eq!(bytes, Bytes::from_static(b"project: project1"));
            }
            _ => panic!(),
        }

        let req = TestRequest::with_uri("/aa-project1/path1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_scope_with_state() {
        struct State;

        let app = App::new()
            .scope("/app", |scope| {
                scope.with_state("/t1", State, |scope| {
                    scope.resource("/path1", |r| r.f(|_| HttpResponse::Created()))
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/t1/path1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::CREATED);
    }

    #[test]
    fn test_scope_with_state_root() {
        struct State;

        let app = App::new()
            .scope("/app", |scope| {
                scope.with_state("/t1", State, |scope| {
                    scope
                        .resource("", |r| r.f(|_| HttpResponse::Ok()))
                        .resource("/", |r| r.f(|_| HttpResponse::Created()))
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/t1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);

        let req = TestRequest::with_uri("/app/t1/").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::CREATED);
    }

    #[test]
    fn test_scope_with_state_root2() {
        struct State;

        let app = App::new()
            .scope("/app", |scope| {
                scope.with_state("/t1/", State, |scope| {
                    scope.resource("", |r| r.f(|_| HttpResponse::Ok()))
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/t1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/app/t1/").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);
    }

    #[test]
    fn test_scope_with_state_root3() {
        struct State;

        let app = App::new()
            .scope("/app", |scope| {
                scope.with_state("/t1/", State, |scope| {
                    scope.resource("/", |r| r.f(|_| HttpResponse::Ok()))
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/t1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/app/t1/").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_scope_with_state_filter() {
        struct State;

        let app = App::new()
            .scope("/app", |scope| {
                scope.with_state("/t1", State, |scope| {
                    scope
                        .filter(pred::Get())
                        .resource("/path1", |r| r.f(|_| HttpResponse::Ok()))
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/t1/path1")
            .method(Method::POST)
            .context()
            .0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/app/t1/path1")
            .method(Method::GET)
            .context()
            .0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);
    }

    #[test]
    fn test_nested_scope() {
        let app = App::new()
            .scope("/app", |scope| {
                scope.nested("/t1", |scope| {
                    scope.resource("/path1", |r| r.f(|_| HttpResponse::Created()))
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/t1/path1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::CREATED);
    }

    #[test]
    fn test_nested_scope_root() {
        let app = App::new()
            .scope("/app", |scope| {
                scope.nested("/t1", |scope| {
                    scope
                        .resource("", |r| r.f(|_| HttpResponse::Ok()))
                        .resource("/", |r| r.f(|_| HttpResponse::Created()))
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/t1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);

        let req = TestRequest::with_uri("/app/t1/").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::CREATED);
    }

    #[test]
    fn test_nested_scope_filter() {
        let app = App::new()
            .scope("/app", |scope| {
                scope.nested("/t1", |scope| {
                    scope
                        .filter(pred::Get())
                        .resource("/path1", |r| r.f(|_| HttpResponse::Ok()))
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/t1/path1")
            .method(Method::POST)
            .context()
            .0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/app/t1/path1")
            .method(Method::GET)
            .context()
            .0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::OK);
    }

    #[test]
    fn test_nested_scope_with_variable_segment() {
        let app = App::new()
            .scope("/app", |scope| {
                scope.nested("/{project_id}", |scope| {
                    scope.resource("/path1", |r| {
                        r.f(|r| {
                            HttpResponse::Created().body(format!(
                                "project: {}",
                                &r.match_info()["project_id"]
                            ))
                        })
                    })
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/project_1/path1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::CREATED);

        match resp.as_msg().1.body() {
            &Body::Binary(ref b) => {
                let bytes: Bytes = b.clone().into();
                assert_eq!(bytes, Bytes::from_static(b"project: project_1"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_nested2_scope_with_variable_segment() {
        let app = App::new()
            .scope("/app", |scope| {
                scope.nested("/{project}", |scope| {
                    scope.nested("/{id}", |scope| {
                        scope.resource("/path1", |r| {
                            r.f(|r| {
                                HttpResponse::Created().body(format!(
                                    "project: {} - {}",
                                    &r.match_info()["project"],
                                    &r.match_info()["id"],
                                ))
                            })
                        })
                    })
                })
            })
            .finish();

        let req = TestRequest::with_uri("/app/test/1/path1").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::CREATED);

        match resp.as_msg().1.body() {
            &Body::Binary(ref b) => {
                let bytes: Bytes = b.clone().into();
                assert_eq!(bytes, Bytes::from_static(b"project: test - 1"));
            }
            _ => panic!(),
        }

        let req = TestRequest::with_uri("/app/test/1/path2").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_default_resource() {
        let app = App::new()
            .scope("/app", |scope| {
                scope
                    .resource("/path1", |r| r.f(|_| HttpResponse::Ok()))
                    .default_resource(|r| r.f(|_| HttpResponse::BadRequest()))
            })
            .finish();

        let req = TestRequest::with_uri("/app/path2").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::BAD_REQUEST);

        let req = TestRequest::with_uri("/path2").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_default_resource_propagation() {
        let app = App::new()
            .scope("/app1", |scope| {
                scope.default_resource(|r| r.f(|_| HttpResponse::BadRequest()))
            })
            .scope("/app2", |scope| scope)
            .default_resource(|r| r.f(|_| HttpResponse::MethodNotAllowed()))
            .finish();

        let req = TestRequest::with_uri("/non-exist").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::METHOD_NOT_ALLOWED);

        let req = TestRequest::with_uri("/app1/non-exist").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::BAD_REQUEST);

        let req = TestRequest::with_uri("/app2/non-exist").context().0;
        let resp = app.run(req);
        assert_eq!(resp.as_msg().1.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
