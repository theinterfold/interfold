// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! HTTP access log lines that name the route, not the caller or the request path.

use actix_web::{dev::ServiceRequest, middleware::Logger};

/// The log target of the access log lines.
pub const ACCESS_LOG_TARGET: &str = "crisp::access";

/// The access log middleware.
///
/// Each line holds the method, the route template, the status, the response size, and the
/// duration. It holds no caller address and no request path. A path such as
/// `/voting/availability/{job_id}` carries an identifier that anyone can compute from public chain
/// data, so a line with the caller address and the path would link a caller to one input. A path
/// that matches no route is logged as `-`, never as the raw path.
pub fn access_logger() -> Logger {
    Logger::new(r#""%{method}xi %{route}xi" %s %b %T"#)
        .custom_request_replace("method", |request| request.method().to_string())
        .custom_request_replace("route", route_template)
        .log_target(ACCESS_LOG_TARGET)
}

/// The template of the route that matches the request path, or `-` when no route matches.
fn route_template(request: &ServiceRequest) -> String {
    request.match_pattern().unwrap_or_else(|| "-".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use std::sync::{Mutex, Once};

    /// Keeps the access log lines, so a test can read what the middleware wrote.
    struct AccessLogCapture(Mutex<Vec<String>>);

    impl log::Log for AccessLogCapture {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.target() == ACCESS_LOG_TARGET
        }

        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                self.0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    static CAPTURE: AccessLogCapture = AccessLogCapture(Mutex::new(Vec::new()));

    /// Install the capture as the process logger. The logger is process-wide and can be set only
    /// once, so every test of this module shares it and reads only its own lines.
    fn capture() -> &'static AccessLogCapture {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&CAPTURE).expect("no other logger is installed in the test binary");
            log::set_max_level(log::LevelFilter::Info);
        });
        &CAPTURE
    }

    /// An access log line names the route template and never the identifier in the path or the
    /// caller address. The handlers have no application data here and answer with an error, and
    /// the middleware logs the request all the same.
    #[actix_web::test]
    async fn access_log_lines_hold_the_route_and_not_the_caller_or_the_path() {
        let capture = capture();
        let job_id = format!("0x{}", "5a".repeat(32));
        let caller = "203.0.113.7:4567".parse().unwrap();
        let app = test::init_service(
            App::new()
                .wrap(access_logger())
                .configure(super::super::routes::setup_routes),
        )
        .await;

        let requests = [
            test::TestRequest::get()
                .uri(&format!("/voting/availability/{job_id}"))
                .peer_addr(caller)
                .to_request(),
            test::TestRequest::post()
                .uri("/voting/broadcast")
                .peer_addr(caller)
                .set_json(serde_json::json!({ "round_id": "1", "encoded_proof": "0x00" }))
                .to_request(),
            test::TestRequest::get()
                .uri(&format!("/no-such-route/{job_id}"))
                .peer_addr(caller)
                .to_request(),
        ];
        for request in requests {
            // The middleware writes the line when the response body is dropped.
            drop(test::call_service(&app, request).await);
        }

        let lines = capture
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with(r#""GET /voting/availability/{job_id}" "#)),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with(r#""POST /voting/broadcast" "#)),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.starts_with(r#""GET -" "#)),
            "{lines:?}"
        );
        for line in &lines {
            assert!(
                !line.contains("5a5a5a"),
                "the path identifier is logged: {line}"
            );
            assert!(
                !line.contains("203.0.113.7"),
                "the caller is logged: {line}"
            );
        }
    }
}
