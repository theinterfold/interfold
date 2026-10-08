// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod chain;
mod members;
mod proposals;
mod rounds;
mod scan;
mod state;
mod voting;

use actix_web::{http::StatusCode, web, HttpResponse};

use crate::server::models::JsonResponse;

/// A `{"response": message}` body with `status`.
pub(super) fn json_message(status: StatusCode, message: impl Into<String>) -> HttpResponse {
    HttpResponse::build(status).json(JsonResponse {
        response: message.into(),
    })
}

/// The 503 that every route returns when the upstream RPC cannot be reached.
pub(super) fn upstream_unavailable() -> HttpResponse {
    json_message(StatusCode::SERVICE_UNAVAILABLE, "Upstream RPC unavailable")
}

pub fn setup_routes(config: &mut web::ServiceConfig) {
    state::setup_routes(config);
    voting::setup_routes(config);
    rounds::setup_routes(config);
    chain::setup_routes(config);
    members::setup_routes(config);
    proposals::setup_routes(config);
}
