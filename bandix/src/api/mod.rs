pub mod connection;
pub mod dns;
pub mod traffic;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpStream;

/// API 响应结构
#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub status: String,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            status: "success".to_string(),
            data: Some(data),
            message: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            status: "error".to_string(),
            data: None,
            message: Some(message),
        }
    }
}

/// HTTP 请求信息
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub body: Option<String>,
}

/// HTTP 响应
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

impl HttpResponse {
    pub fn ok(body: String) -> Self {
        Self {
            status: 200,
            content_type: "application/json".to_string(),
            body,
        }
    }

    pub fn error(status: u16, message: String) -> Self {
        let error_response = ApiResponse::<()>::error(message);
        let body = serde_json::to_string(&error_response)
            .unwrap_or_else(|_| r#"{"status":"error","message":"JSON serialization failed"}"#.to_string());
        Self {
            status,
            content_type: "application/json".to_string(),
            body,
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain".to_string(),
            body: "Not Found".to_string(),
        }
    }
}

/// 不同模块的 API 处理程序枚举
#[derive(Clone)]
pub enum ApiHandler {
    Traffic(crate::api::traffic::TrafficApiHandler),
    Dns(crate::api::dns::DnsApiHandler),
    Connection(crate::api::connection::ConnectionApiHandler),
}

impl ApiHandler {
    pub fn module_name(&self) -> &'static str {
        match self {
            ApiHandler::Traffic(_) => "traffic",
            ApiHandler::Dns(_) => "dns",
            ApiHandler::Connection(_) => "connection",
        }
    }

    pub fn supported_routes(&self) -> Vec<&'static str> {
        match self {
            ApiHandler::Traffic(handler) => handler.supported_routes(),
            ApiHandler::Dns(handler) => handler.supported_routes(),
            ApiHandler::Connection(handler) => handler.supported_routes(),
        }
    }

    pub async fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        match self {
            ApiHandler::Traffic(handler) => handler.handle_request(request).await,
            ApiHandler::Dns(handler) => handler.handle_request(request).await,
            ApiHandler::Connection(handler) => handler.handle_request(request).await,
        }
    }
}

/// API 路由器，用于管理模块 API 处理程序
#[derive(Clone)]
pub struct ApiRouter {
    handlers: HashMap<String, ApiHandler>,
    started_at: Instant,
    policy_engine: Option<SharedPolicyEngine>,
}

pub type SharedPolicyEngine = Arc<Mutex<Box<dyn crate::policy::TrafficPolicyEngine + Send>>>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineCapabilities {
    product: &'static str,
    version: &'static str,
    interface_version: &'static str,
    engine: &'static str,
    lineage: &'static str,
    data_plane: &'static str,
    modules: Vec<String>,
    protocol_compatibility: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineHealthDocument {
    state: &'static str,
    pid: u32,
    uptime_seconds: u64,
    resident_memory_kib: Option<u64>,
    data_plane: &'static str,
    policy_interface_version: &'static str,
    max_device_policies: usize,
    max_http_connections: usize,
    dns_storage_default: bool,
    traffic_storage_default: bool,
    reasons: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyApplyRequest {
    plan: crate::policy::PolicyPlan,
    request: crate::policy::PolicyMutationRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyRollbackRequest {
    revision: u64,
}

#[derive(Serialize)]
struct PolicyErrorEnvelope {
    status: &'static str,
    error: crate::policy::PolicyError,
}

impl ApiRouter {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            started_at: Instant::now(),
            policy_engine: None,
        }
    }

    pub fn set_policy_engine(&mut self, engine: SharedPolicyEngine) {
        self.policy_engine = Some(engine);
    }

    /// Register an API handler for a module
    pub fn register_handler(&mut self, handler: ApiHandler) {
        self.handlers.insert(handler.module_name().to_string(), handler);
    }

    /// Route a request to the appropriate handler
    pub async fn route_request(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        if request.path == "/api/v1/system/capabilities" {
            if request.method != "GET" {
                return Ok(HttpResponse::error(405, "Method not allowed".to_string()));
            }

            let mut modules: Vec<String> = self.handlers.keys().cloned().collect();
            modules.sort();
            let body = serde_json::to_string(&ApiResponse::success(EngineCapabilities {
                product: "quickstart-netpolicy",
                version: env!("CARGO_PKG_VERSION"),
                interface_version: crate::policy::POLICY_INTERFACE_VERSION,
                engine: "quickstart-native",
                lineage: "bandix-v0.12.10",
                data_plane: "ebpf-tc",
                modules,
                protocol_compatibility: vec!["bandix-http-v0.12"],
            }))?;
            return Ok(HttpResponse::ok(body));
        }
        if request.path == "/api/v1/system/health" {
            if request.method != "GET" {
                return Ok(HttpResponse::error(405, "Method not allowed".to_string()));
            }
            let (state, data_plane, reasons) = match &self.policy_engine {
                Some(engine) => match engine.lock() {
                    Ok(engine) => {
                        let health = engine.health();
                        let state = match health.state {
                            crate::policy::EngineHealthState::Healthy => "healthy",
                            crate::policy::EngineHealthState::Degraded => "degraded",
                            crate::policy::EngineHealthState::Unavailable => "unavailable",
                            crate::policy::EngineHealthState::Conflict => "conflict",
                        };
                        (state, "ready", health.reasons)
                    }
                    Err(_) => ("unavailable", "unavailable", vec!["policy engine lock is poisoned".to_string()]),
                },
                None if self.handlers.contains_key("traffic") => {
                    ("degraded", "initializing", vec!["policy engine is not initialized".to_string()])
                }
                None => ("healthy", "disabled", Vec::new()),
            };
            let body = serde_json::to_string(&ApiResponse::success(EngineHealthDocument {
                state,
                pid: std::process::id(),
                uptime_seconds: self.started_at.elapsed().as_secs(),
                resident_memory_kib: resident_memory_kib(),
                data_plane,
                policy_interface_version: crate::policy::POLICY_INTERFACE_VERSION,
                max_device_policies: crate::policy::MAX_DEVICE_POLICIES,
                max_http_connections: crate::web::MAX_CONNECTIONS,
                dns_storage_default: false,
                traffic_storage_default: false,
                reasons,
            }))?;
            return Ok(HttpResponse::ok(body));
        }
        if request.path == "/api/v1/policies" && request.method == "GET" {
            return Ok(self.with_policy_engine(|engine| engine.inspect()));
        }
        if request.path == "/api/v1/policies/plan" && request.method == "POST" {
            let mutation: crate::policy::PolicyMutationRequest = parse_json_body(request)?;
            return Ok(self.with_policy_engine(|engine| engine.plan(&mutation)));
        }
        if request.path == "/api/v1/policies/apply" && request.method == "POST" {
            let payload: PolicyApplyRequest = parse_json_body(request)?;
            return Ok(self.with_policy_engine(|engine| engine.apply(&payload.plan, &payload.request)));
        }
        if request.path == "/api/v1/policies/verify" && request.method == "POST" {
            let snapshot: crate::policy::PolicySnapshot = parse_json_body(request)?;
            return Ok(self.with_policy_engine(|engine| engine.verify(&snapshot).map(|_| snapshot)));
        }
        if request.path == "/api/v1/policies/rollback" && request.method == "POST" {
            let payload: PolicyRollbackRequest = parse_json_body(request)?;
            return Ok(self.with_policy_engine(|engine| engine.rollback(payload.revision)));
        }

        // Try to find a handler that supports this route
        for handler in self.handlers.values() {
            for route in handler.supported_routes() {
                if request.path.starts_with(route) {
                    return handler.handle_request(request).await;
                }
            }
        }

        // No handler found
        Ok(HttpResponse::not_found())
    }

    fn with_policy_engine<T: Serialize>(
        &self,
        operation: impl FnOnce(&mut dyn crate::policy::TrafficPolicyEngine) -> Result<T, crate::policy::PolicyError>,
    ) -> HttpResponse {
        let Some(engine) = &self.policy_engine else {
            return policy_error_response(crate::policy::PolicyError {
                code: crate::policy::PolicyErrorCode::Unavailable,
                message: "policy engine is unavailable".to_string(),
                field: None,
            });
        };
        let Ok(mut engine) = engine.lock() else {
            return policy_error_response(crate::policy::PolicyError {
                code: crate::policy::PolicyErrorCode::Unavailable,
                message: "policy engine lock is poisoned".to_string(),
                field: None,
            });
        };
        match operation(engine.as_mut()) {
            Ok(value) => HttpResponse::ok(serde_json::to_string(&ApiResponse::success(value)).unwrap_or_default()),
            Err(error) => policy_error_response(error),
        }
    }
}

fn parse_json_body<T: for<'de> Deserialize<'de>>(request: &HttpRequest) -> Result<T, anyhow::Error> {
    let body = request
        .body
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("request body is required"))?;
    serde_json::from_str(body).map_err(Into::into)
}

fn policy_error_response(error: crate::policy::PolicyError) -> HttpResponse {
    let status = match error.code {
        crate::policy::PolicyErrorCode::ValidationFailed | crate::policy::PolicyErrorCode::CapacityExceeded => 400,
        crate::policy::PolicyErrorCode::RevisionConflict | crate::policy::PolicyErrorCode::Conflict => 409,
        crate::policy::PolicyErrorCode::Unavailable => 503,
        crate::policy::PolicyErrorCode::VerificationFailed | crate::policy::PolicyErrorCode::RollbackFailed => 500,
    };
    HttpResponse {
        status,
        content_type: "application/json".to_string(),
        body: serde_json::to_string(&PolicyErrorEnvelope { status: "error", error }).unwrap_or_default(),
    }
}

fn resident_memory_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubPolicyEngine;

    impl crate::policy::TrafficPolicyEngine for StubPolicyEngine {
        fn inspect(&self) -> Result<crate::policy::PolicySnapshot, crate::policy::PolicyError> {
            Ok(crate::policy::PolicySnapshot {
                schema_version: 1,
                revision: 7,
                policies: Vec::new(),
            })
        }

        fn plan(&self, request: &crate::policy::PolicyMutationRequest) -> Result<crate::policy::PolicyPlan, crate::policy::PolicyError> {
            Ok(crate::policy::PolicyPlan {
                id: "plan-1".to_string(),
                base_revision: request.expected_revision,
                next_revision: request.expected_revision + 1,
                changes: Vec::new(),
                warnings: Vec::new(),
            })
        }

        fn apply(
            &mut self,
            _plan: &crate::policy::PolicyPlan,
            _request: &crate::policy::PolicyMutationRequest,
        ) -> Result<crate::policy::PolicySnapshot, crate::policy::PolicyError> {
            self.inspect()
        }

        fn verify(&self, _snapshot: &crate::policy::PolicySnapshot) -> Result<(), crate::policy::PolicyError> {
            Ok(())
        }

        fn rollback(&mut self, _revision: u64) -> Result<crate::policy::PolicySnapshot, crate::policy::PolicyError> {
            self.inspect()
        }

        fn health(&self) -> crate::policy::EngineHealth {
            crate::policy::EngineHealth {
                state: crate::policy::EngineHealthState::Healthy,
                interface: "br-lan".to_string(),
                revision: 7,
                reasons: Vec::new(),
            }
        }
    }

    #[tokio::test]
    async fn capability_route_identifies_independent_engine() {
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/system/capabilities".to_string(),
            query_params: HashMap::new(),
            body: None,
        };

        let response = ApiRouter::new().route_request(&request).await.unwrap();
        assert_eq!(response.status, 200);
        let document: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(document["data"]["product"], "quickstart-netpolicy");
        assert_eq!(document["data"]["interfaceVersion"], "1");
        assert_eq!(document["data"]["engine"], "quickstart-native");
    }

    #[tokio::test]
    async fn health_route_exposes_bounded_runtime_defaults() {
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/system/health".to_string(),
            query_params: HashMap::new(),
            body: None,
        };
        let response = ApiRouter::new().route_request(&request).await.unwrap();
        let document: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(document["data"]["state"], "healthy");
        assert_eq!(document["data"]["maxDevicePolicies"], 1024);
        assert_eq!(document["data"]["maxHttpConnections"], 32);
        assert_eq!(document["data"]["dnsStorageDefault"], false);
        assert_eq!(document["data"]["trafficStorageDefault"], false);
    }

    #[tokio::test]
    async fn policy_route_reports_stable_unavailable_error_without_engine() {
        let response = ApiRouter::new()
            .route_request(&HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/policies".to_string(),
                query_params: HashMap::new(),
                body: None,
            })
            .await
            .unwrap();
        assert_eq!(response.status, 503);
        assert!(response.body.contains("unavailable"));
    }

    #[tokio::test]
    async fn policy_routes_expose_the_transaction_engine() {
        let mut router = ApiRouter::new();
        router.set_policy_engine(Arc::new(Mutex::new(Box::new(StubPolicyEngine))));
        let inspect = router
            .route_request(&HttpRequest {
                method: "GET".to_string(),
                path: "/api/v1/policies".to_string(),
                query_params: HashMap::new(),
                body: None,
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&inspect.body).unwrap()["data"]["revision"],
            7
        );

        let plan = router
            .route_request(&HttpRequest {
                method: "POST".to_string(),
                path: "/api/v1/policies/plan".to_string(),
                query_params: HashMap::new(),
                body: Some(
                    r#"{"expectedRevision":7,"idempotencyKey":"key","owner":{"product":"quickstart","instance":"local"},"policies":[]}"#
                        .to_string(),
                ),
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&plan.body).unwrap()["data"]["nextRevision"],
            8
        );
    }
}

/// 从原始字节解析 HTTP 请求
pub fn parse_http_request(request_bytes: &[u8]) -> Result<HttpRequest, anyhow::Error> {
    let request_str = String::from_utf8_lossy(request_bytes);
    let lines: Vec<&str> = request_str.lines().collect();

    if lines.is_empty() {
        return Err(anyhow::anyhow!("Empty request"));
    }

    // 解析request line
    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid request line"));
    }

    let method = parts[0].to_string();
    let path_with_query = parts[1];

    // 分割path and query parameters
    let (path, query_str) = if let Some(pos) = path_with_query.find('?') {
        (path_with_query[..pos].to_string(), Some(&path_with_query[pos + 1..]))
    } else {
        (path_with_query.to_string(), None)
    };

    // 解析query parameters
    let mut query_params = HashMap::new();
    if let Some(query) = query_str {
        for param in query.split('&') {
            if let Some(eq_pos) = param.find('=') {
                let key = param[..eq_pos].to_string();
                let value = param[eq_pos + 1..].to_string();
                query_params.insert(key, value);
            }
        }
    }

    // 解析body (if present)
    let body = if let Some(body_start) = request_str.find("\r\n\r\n") {
        Some(request_str[body_start + 4..].to_string())
    } else {
        None
    };

    Ok(HttpRequest {
        method,
        path,
        query_params,
        body,
    })
}

/// 向客户端发送 HTTP 响应
pub async fn send_http_response(stream: &mut TcpStream, response: &HttpResponse) -> Result<(), anyhow::Error> {
    use tokio::io::AsyncWriteExt;

    let status_text = match response.status {
        200 => "OK",
        400 => "BAD REQUEST",
        405 => "METHOD NOT ALLOWED",
        409 => "CONFLICT",
        408 => "REQUEST TIMEOUT",
        413 => "CONTENT TOO LARGE",
        404 => "Not Found",
        500 => "INTERNAL SERVER ERROR",
        503 => "SERVICE UNAVAILABLE",
        _ => "UNKNOWN",
    };

    let http_response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
        response.status,
        status_text,
        response.content_type,
        response.body.len(),
        response.body
    );

    stream.write_all(http_response.as_bytes()).await?;
    Ok(())
}
