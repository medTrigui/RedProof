use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Once};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use http::Method;
use rustls::client::ClientConnection;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore, StreamOwned};
use rustls_native_certs::load_native_certs;
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::commit::Transcript;
use crate::evaluate::HeaderMap;

const USER_AGENT: &str = concat!("RedProof/", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT_SECS: u64 = 20;

pub struct CaptureOptions {
    pub url: Url,
    pub method: Method,
    pub max_body_bytes: usize,
    pub timeout: Option<Duration>,
}

pub struct CaptureRecord {
    pub requested_url: Url,
    pub domain: String,
    pub method: Method,
    pub captured_at: DateTime<Utc>,
    pub tls: TlsMetadata,
    pub response: HttpResponse,
    pub canonical_handshake: Vec<u8>,
    pub canonical_app_data: Vec<u8>,
    pub headers: HeaderMap,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsMetadata {
    pub version: String,
    pub cipher: String,
    pub cert_fingerprints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpResponse {
    pub http_version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<HeaderEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

impl CaptureRecord {
    pub fn transcript(&self) -> Transcript {
        Transcript {
            handshake: self.canonical_handshake.clone(),
            app_data: self.canonical_app_data.clone(),
        }
    }
}

pub fn capture(options: &CaptureOptions) -> Result<CaptureRecord> {
    install_crypto_provider();
    if options.url.scheme() != "https" {
        bail!("only https:// URLs are supported (got {})", options.url);
    }
    let domain = options
        .url
        .host_str()
        .ok_or_else(|| anyhow!("URL missing host"))?
        .to_string();
    let port = options.url.port_or_known_default().unwrap_or(443);
    let path = if options.url.path().is_empty() {
        "/"
    } else {
        options.url.path()
    };
    let mut target = path.to_string();
    if let Some(query) = options.url.query() {
        target.push('?');
        target.push_str(query);
    }

    let addr = format!("{}:{}", domain, port);
    let timeout = options
        .timeout
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    let tcp =
        TcpStream::connect(&addr).with_context(|| format!("failed to connect to {}", addr))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    let config = build_tls_config()?;
    let server_name =
        ServerName::try_from(domain.clone()).map_err(|_| anyhow!("invalid DNS name"))?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).context("failed to negotiate TLS")?;
    let mut stream = StreamOwned::new(connection, tcp);

    let request = build_request(&options.method, &domain, &target);
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }

    let StreamOwned { conn, .. } = stream;
    let tls = extract_tls_metadata(&conn, &domain);

    let (response, headers, header_map) = parse_http_response(&raw, options.max_body_bytes)?;
    let canonical_handshake = canonicalize_handshake(&tls, &domain)?;
    let canonical_app_data = canonicalize_app_data(&response, &headers)?;

    Ok(CaptureRecord {
        requested_url: options.url.clone(),
        domain,
        method: options.method.clone(),
        captured_at: Utc::now(),
        tls,
        response,
        canonical_handshake,
        canonical_app_data,
        headers: header_map,
    })
}

fn build_tls_config() -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    for cert in load_native_certs().context("failed to load system certificates")? {
        root_store
            .add(cert)
            .map_err(|_| anyhow!("unable to add root certificate"))?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(config)
}

fn build_request(method: &Method, host: &str, target: &str) -> String {
    format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        method = method.as_str(),
        target = target,
        host = host,
        ua = USER_AGENT
    )
}

fn parse_http_response(
    raw: &[u8],
    max_body_bytes: usize,
) -> Result<(HttpResponse, Vec<HeaderEntry>, HeaderMap)> {
    let split = find_header_split(raw).context("malformed HTTP response")?;
    let (header_bytes, body_bytes) = raw.split_at(split);
    let body = &body_bytes[4..];
    let header_text = String::from_utf8_lossy(header_bytes);
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| anyhow!("missing status line"))?;
    let (http_version, status_code, reason) = parse_status_line(status_line)?;

    let mut header_entries = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            header_entries.push(HeaderEntry {
                name: name.trim().to_ascii_lowercase(),
                value: value.trim().to_string(),
            });
        }
    }
    header_entries.sort_by(|a, b| a.name.cmp(&b.name));

    let mut header_map = HeaderMap::default();
    for entry in &header_entries {
        header_map
            .entry(entry.name.clone())
            .or_default()
            .push(entry.value.clone());
    }

    let mut body_vec = body.to_vec();
    let mut truncated = false;
    if body_vec.len() > max_body_bytes {
        body_vec.truncate(max_body_bytes);
        truncated = true;
    }

    let response = HttpResponse {
        http_version: http_version.to_string(),
        status_code,
        reason: reason.to_string(),
        headers: header_entries.clone(),
        body: body_vec,
        body_truncated: truncated,
    };

    Ok((response, header_entries, header_map))
}

fn find_header_split(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_status_line(line: &str) -> Result<(&str, u16, &str)> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts
        .next()
        .ok_or_else(|| anyhow!("missing status code"))?
        .parse::<u16>()
        .context("invalid status code")?;
    let reason = parts.next().unwrap_or("");
    Ok((version, code, reason))
}

fn canonicalize_handshake(tls: &TlsMetadata, domain: &str) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct CanonicalHandshake<'a> {
        domain: &'a str,
        version: &'a str,
        cipher: &'a str,
        alpn: Option<&'a String>,
        cert_fingerprints: &'a [String],
    }

    serde_json::to_vec(&CanonicalHandshake {
        domain,
        version: &tls.version,
        cipher: &tls.cipher,
        alpn: tls.alpn.as_ref(),
        cert_fingerprints: &tls.cert_fingerprints,
    })
    .context("failed to canonicalize handshake")
}

fn canonicalize_app_data(response: &HttpResponse, headers: &[HeaderEntry]) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct CanonicalAppData<'a> {
        status_code: u16,
        reason: &'a str,
        headers: &'a [HeaderEntry],
        body_base64: String,
        body_truncated: bool,
    }

    serde_json::to_vec(&CanonicalAppData {
        status_code: response.status_code,
        reason: &response.reason,
        headers,
        body_base64: B64.encode(&response.body),
        body_truncated: response.body_truncated,
    })
    .context("failed to canonicalize response")
}

fn extract_tls_metadata(conn: &ClientConnection, domain: &str) -> TlsMetadata {
    let version = conn
        .protocol_version()
        .map(|v| match v {
            ProtocolVersion::TLSv1_3 => "TLS1.3".to_string(),
            ProtocolVersion::TLSv1_2 => "TLS1.2".to_string(),
            other => format!("{:?}", other),
        })
        .unwrap_or_else(|| "UNKNOWN".to_string());

    let cipher = conn
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "UNKNOWN".into());

    let alpn = conn
        .alpn_protocol()
        .map(|proto| String::from_utf8_lossy(proto).to_string());

    let fingerprints = conn
        .peer_certificates()
        .map(|certs| {
            certs
                .iter()
                .map(|cert| {
                    let digest = Sha256::digest(cert.as_ref());
                    format!("sha256:{:x}", digest)
                })
                .collect()
        })
        .unwrap_or_else(|| vec![format!("domain-only:{}", domain)]);

    TlsMetadata {
        version,
        cipher,
        cert_fingerprints: fingerprints,
        alpn,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use serde_json::Value;

    #[test]
    fn parse_http_response_normalizes_headers_and_body() {
        let raw =
            b"HTTP/1.1 200 OK\r\nServer: Example\r\nX-Test: One\r\nX-Test: Two\r\n\r\nHello body"
                .to_vec();
        let (response, headers, map) = parse_http_response(&raw, 1024).expect("parse http");

        assert_eq!(response.status_code, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(headers[0].name, "server");
        assert_eq!(headers[0].value, "Example");
        let x_test = map.get("x-test").expect("x-test header");
        assert_eq!(x_test, &vec![String::from("One"), String::from("Two")]);
        assert_eq!(response.body, b"Hello body");
        assert!(!response.body_truncated);
    }

    #[test]
    fn parse_http_response_truncates_body_when_needed() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: Example\r\n\r\nHello body".to_vec();
        let (response, _, _) = parse_http_response(&raw, 4).expect("parse http");
        assert_eq!(response.body, b"Hell");
        assert!(response.body_truncated);
    }

    #[test]
    fn canonicalize_handshake_outputs_expected_json() {
        let tls = TlsMetadata {
            version: "TLS1.3".into(),
            cipher: "TLS_AES_128_GCM_SHA256".into(),
            cert_fingerprints: vec!["sha256:deadbeef".into()],
            alpn: Some("h2".into()),
        };
        let bytes = canonicalize_handshake(&tls, "example.com").expect("handshake");
        let json: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["domain"], "example.com");
        assert_eq!(json["version"], "TLS1.3");
        assert_eq!(json["cipher"], "TLS_AES_128_GCM_SHA256");
        assert_eq!(json["alpn"], "h2");
    }

    #[test]
    fn capture_record_transcript_clones_buffers() {
        let record = CaptureRecord {
            requested_url: Url::parse("https://example.com").unwrap(),
            domain: "example.com".into(),
            method: Method::GET,
            captured_at: Utc::now(),
            tls: TlsMetadata {
                version: String::new(),
                cipher: String::new(),
                cert_fingerprints: vec![],
                alpn: None,
            },
            response: HttpResponse {
                http_version: "HTTP/1.1".into(),
                status_code: 200,
                reason: "OK".into(),
                headers: vec![],
                body: vec![],
                body_truncated: false,
            },
            canonical_handshake: b"handshake".to_vec(),
            canonical_app_data: b"app".to_vec(),
            headers: HeaderMap::new(),
        };

        let transcript = record.transcript();
        assert_eq!(transcript.handshake, b"handshake");
        assert_eq!(transcript.app_data, b"app");
    }
}

fn install_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install ring crypto provider");
    });
}
