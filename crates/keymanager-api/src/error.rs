use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::RateLimited { retry_after_secs } => {
                let body = serde_json::json!({ "code": 429, "message": "rate limited" });
                let mut response =
                    (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
                if let Ok(val) = retry_after_secs.to_string().parse() {
                    response.headers_mut().insert("Retry-After", val);
                }
                response
            }
            other => {
                let (status, message) = match &other {
                    ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
                    ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
                    ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
                    ApiError::RateLimited { .. } => unreachable!(),
                };
                let body = serde_json::json!({ "message": message });
                (status, axum::Json(body)).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_not_found_returns_404_with_json_body() {
        let error = ApiError::NotFound("validator not found".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "validator not found");
    }
}
