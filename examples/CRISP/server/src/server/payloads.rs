// SPDX-License-Identifier: LGPL-3.0-only

use actix_web::web;

// Allow a maximum-size hex-encoded DA object plus its proof and envelope.
// Retain Actix's smaller default JSON limit on ordinary read endpoints.
const ENCRYPTED_JSON_LIMIT: usize = 4 * e3_data_availability::MAX_OBJECT_BYTES;

pub fn encrypted_json() -> web::JsonConfig {
    web::JsonConfig::default().limit(ENCRYPTED_JSON_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test, App, HttpResponse};

    async fn accept(_: web::Json<serde_json::Value>) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[actix_web::test]
    async fn encrypted_payload_limit_is_bounded_and_route_local() {
        let app = test::init_service(
            App::new()
                .service(
                    web::resource("/encrypted")
                        .app_data(encrypted_json())
                        .route(web::post().to(accept)),
                )
                .route("/read", web::post().to(accept)),
        )
        .await;
        let payload =
            serde_json::json!({"ciphertext": "ab".repeat(e3_data_availability::MAX_OBJECT_BYTES)});
        let accepted = test::TestRequest::post()
            .uri("/encrypted")
            .set_json(&payload)
            .to_request();
        assert_eq!(
            test::call_service(&app, accepted).await.status(),
            StatusCode::OK
        );
        let ordinary = test::TestRequest::post()
            .uri("/read")
            .set_json(&payload)
            .to_request();
        assert_eq!(
            test::call_service(&app, ordinary).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let oversized = test::TestRequest::post()
            .uri("/encrypted")
            .set_json(serde_json::json!({"ciphertext": "a".repeat(ENCRYPTED_JSON_LIMIT)}))
            .to_request();
        assert_eq!(
            test::call_service(&app, oversized).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
