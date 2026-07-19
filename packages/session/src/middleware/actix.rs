use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    http::header,
    Error, FromRequest, HttpMessage, HttpRequest,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use std::{rc::Rc, sync::Arc};

use crate::{SessionError, TokenClaims, TokenManager};

/// Actix middleware that validates JWT on every request.
///
/// # Usage
/// ```ignore
/// App::new()
///     .app_data(web::Data::new(manager))
///     .wrap(JwtMiddleware::default())
/// ```
pub struct JwtMiddleware {
    _private: (),
}

impl Default for JwtMiddleware {
    fn default() -> Self {
        Self { _private: () }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareService {
            service: Rc::new(service),
        })
    }
}

pub struct JwtMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        Box::pin(async move {
            let manager = req
                .app_data::<actix_web::web::Data<Arc<TokenManager>>>()
                .map(|d| d.get_ref().clone());

            if let Some(manager) = manager {
                if let Some(auth) = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                {
                    match manager.verify(auth) {
                        Ok(claims) => {
                            req.extensions_mut().insert(claims);
                        }
                        Err(SessionError::Expired(_)) => {
                            return Err(ErrorUnauthorized("token expired"));
                        }
                        Err(_) => {
                            return Err(ErrorUnauthorized("invalid token"));
                        }
                    }
                }
            }

            svc.call(req).await
        })
    }
}

impl FromRequest for TokenClaims {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        match req.extensions().get::<TokenClaims>() {
            Some(claims) => ok(claims.clone()),
            None => ok(TokenClaims {
                sub: String::new(),
                username: String::new(),
                token_type: crate::token::TokenType::Access,
                iat: 0,
                exp: 0,
                iss: String::new(),
                jti: String::new(),
                sid: None,
                roles: Vec::new(),
            }),
        }
    }
}
