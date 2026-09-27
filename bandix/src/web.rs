use crate::api::{parse_http_request, send_http_response, ApiRouter};
use crate::command::Options;
use chrono::Local;
use log::{debug, error, info};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
pub(crate) const MAX_CONNECTIONS: usize = 32;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// 简单的 HTTP 服务器，仅依赖 tokio
pub async fn start_server(options: Options, api_router: ApiRouter, shutdown_notify: Arc<tokio::sync::Notify>) -> Result<(), anyhow::Error> {
    // In release mode, only listen on localhost for security
    // In debug mode, listen on all interfaces for easier development
    let host = if cfg!(debug_assertions) { "0.0.0.0" } else { "127.0.0.1" };
    let addr = format!("{}:{}", host, options.port());
    let listener = TcpListener::bind(&addr).await?;
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    info!("HTTP server listening on {}", addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let api_router = api_router.clone();
                        let permit = Arc::clone(&connections).try_acquire_owned();
                        tokio::spawn(async move {
                            let Ok(_permit) = permit else {
                                let mut stream = stream;
                                let response = crate::api::HttpResponse::error(503, "Server is busy".to_string());
                                let _ = send_http_response(&mut stream, &response).await;
                                return;
                            };
                            if let Err(e) = handle_connection(stream, api_router).await {
                                error!("Error handling connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown_notify.notified() => {
                info!("Web server received shutdown signal, stopping...");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_connection(mut stream: TcpStream, api_router: ApiRouter) -> Result<(), anyhow::Error> {
    let request_bytes = match tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            let status = if error.to_string().contains("too large") { 413 } else { 400 };
            send_http_response(&mut stream, &crate::api::HttpResponse::error(status, error.to_string())).await?;
            return Ok(());
        }
        Err(_) => {
            send_http_response(
                &mut stream,
                &crate::api::HttpResponse::error(408, "Request timeout".to_string()),
            )
            .await?;
            return Ok(());
        }
    };

    // 解析HTTP request
    let request = match parse_http_request(&request_bytes) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse HTTP request: {}", e);
            let response = crate::api::HttpResponse::error(400, "Bad Request".to_string());
            send_http_response(&mut stream, &response).await?;
            return Ok(());
        }
    };

    // Log web request (always at DEBUG level, controlled by log_level parameter)
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let query = if request.query_params.is_empty() {
        String::new()
    } else {
        request
            .query_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    };

    if query.is_empty() {
        debug!("[{}] {} {}", timestamp, request.method, request.path);
    } else {
        debug!("[{}] {} {} | params: {}", timestamp, request.method, request.path, query);
    }

    // Route request to appropriate handler
    let response = match api_router.route_request(&request).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Error handling request: {}", e);
            crate::api::HttpResponse::error(500, "Internal Server Error".to_string())
        }
    };

    // Log web response (always at DEBUG level, controlled by log_level parameter)
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    debug!("[{}] Response: {} | Body: {}", timestamp, response.status, response.body);

    // Send response
    send_http_response(&mut stream, &response).await?;

    Ok(())
}

async fn read_request<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, anyhow::Error> {
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut expected_total = None;
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        if request.len().saturating_add(read) > MAX_REQUEST_BYTES {
            anyhow::bail!("request is too large");
        }
        request.extend_from_slice(&chunk[..read]);

        if expected_total.is_none() {
            if let Some(header_end) = find_header_end(&request) {
                if header_end > MAX_HEADER_BYTES {
                    anyhow::bail!("request header is too large");
                }
                let content_length = content_length(&request[..header_end])?;
                let total = header_end.saturating_add(4).saturating_add(content_length);
                if total > MAX_REQUEST_BYTES {
                    anyhow::bail!("request is too large");
                }
                expected_total = Some(total);
            } else if request.len() > MAX_HEADER_BYTES {
                anyhow::bail!("request header is too large");
            }
        }

        if expected_total.is_some_and(|total| request.len() >= total) {
            request.truncate(expected_total.unwrap());
            return Ok(request);
        }
    }
    if expected_total.is_some_and(|total| request.len() != total) {
        anyhow::bail!("incomplete request body");
    }
    if request.is_empty() {
        anyhow::bail!("empty request");
    }
    Ok(request)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(header: &[u8]) -> Result<usize, anyhow::Error> {
    let header = std::str::from_utf8(header)?;
    for line in header.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding") && !value.trim().eq_ignore_ascii_case("identity") {
            anyhow::bail!("transfer encoding is not supported");
        }
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map_err(|_| anyhow::anyhow!("invalid Content-Length"));
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn reads_a_complete_request_across_chunks() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhe")
                .await
                .unwrap();
            client.write_all(b"llo").await.unwrap();
        });
        let request = read_request(&mut server).await.unwrap();
        writer.await.unwrap();
        assert!(request.ends_with(b"hello"));
    }

    #[tokio::test]
    async fn rejects_oversized_and_incomplete_requests() {
        let oversized = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_REQUEST_BYTES);
        assert!(read_request(&mut oversized.as_bytes())
            .await
            .unwrap_err()
            .to_string()
            .contains("too large"));

        let incomplete = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhi";
        assert!(read_request(&mut incomplete.as_slice())
            .await
            .unwrap_err()
            .to_string()
            .contains("incomplete"));
    }

    #[test]
    fn rejects_chunked_transfer_encoding() {
        assert!(content_length(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked")
            .unwrap_err()
            .to_string()
            .contains("not supported"));
    }
}
