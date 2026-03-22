#[path = "real_server_common.rs"]
mod common;

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::time::Duration;

use common::*;

#[test]
fn tcp_connect_over_real_h3_server() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = test_lock().lock().unwrap();
    if env::var("RUN_REAL_SERVER_H3").ok().as_deref() != Some("1") {
        eprintln!("skipping real h3 integration test; set RUN_REAL_SERVER_H3=1 to enable");
        return Ok(());
    }

    let tcp_ws_url = required_env("OUTLINE_TCP_WS_URL")?;
    let udp_ws_url = env::var("OUTLINE_UDP_WS_URL").ok();
    let password = required_env("SHADOWSOCKS_PASSWORD")?;
    let method =
        env::var("SHADOWSOCKS_METHOD").unwrap_or_else(|_| "chacha20-ietf-poly1305".to_string());
    let target_host = env::var("H3_TEST_TARGET_HOST").unwrap_or_else(|_| "example.com".into());
    let target_port: u16 = env::var("H3_TEST_TARGET_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80);

    let temp = TestDir::new("outline-ws-rust-real-h3")?;
    let proxy_port = reserve_tcp_port()?;
    let config_path = temp.path().join("proxy.toml");

    let mut config = format!(
        r#"
[socks5]
listen = "127.0.0.1:{proxy_port}"

[outline]
tcp_ws_url = "{tcp_ws_url}"
tcp_ws_mode = "h3"
method = "{method}"
password = "{password}"
"#
    );
    if let Some(udp_ws_url) = udp_ws_url {
        config.push_str(&format!(
            r#"
udp_ws_url = "{udp_ws_url}"
udp_ws_mode = "h3"
"#
        ));
    }
    fs::write(&config_path, config)?;

    let log_path = temp.path().join("proxy.log");
    let mut proxy = ProxyProcess::start(&config_path, &log_path)?;
    proxy.wait_ready(proxy_port, Duration::from_secs(15))?;

    let mut stream = socks5_connect(proxy_port, &target_host, target_port).map_err(|err| {
        format!(
            "SOCKS5 CONNECT failed: {err}\nproxy logs:\n{}",
            proxy
                .logs()
                .unwrap_or_else(|_| "<proxy logs unavailable>".into())
        )
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let request = format!("GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;

    let mut response = [0u8; 512];
    let n = stream.read(&mut response).map_err(|err| {
        format!(
            "failed to read tunneled response: {err}\nproxy logs:\n{}",
            proxy
                .logs()
                .unwrap_or_else(|_| "<proxy logs unavailable>".into())
        )
    })?;
    let text = String::from_utf8_lossy(&response[..n]);
    assert!(
        text.starts_with("HTTP/1.1 ") || text.starts_with("HTTP/1.0 "),
        "unexpected HTTP response over tunnel: {text}"
    );

    proxy.stop()?;
    Ok(())
}

#[test]
fn udp_associate_over_real_h3_server() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = test_lock().lock().unwrap();
    if env::var("RUN_REAL_SERVER_H3").ok().as_deref() != Some("1") {
        eprintln!("skipping real h3 integration test; set RUN_REAL_SERVER_H3=1 to enable");
        return Ok(());
    }

    let tcp_ws_url = required_env("OUTLINE_TCP_WS_URL")?;
    let udp_ws_url = required_env("OUTLINE_UDP_WS_URL")?;
    let password = required_env("SHADOWSOCKS_PASSWORD")?;
    let method =
        env::var("SHADOWSOCKS_METHOD").unwrap_or_else(|_| "chacha20-ietf-poly1305".to_string());
    let dns_server = env::var("H3_TEST_DNS_SERVER").unwrap_or_else(|_| "1.1.1.1".into());
    let dns_port: u16 = env::var("H3_TEST_DNS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(53);
    let dns_name = env::var("H3_TEST_DNS_NAME").unwrap_or_else(|_| "example.com".into());

    let temp = TestDir::new("outline-ws-rust-real-h3")?;
    let proxy_port = reserve_tcp_port()?;
    let config_path = temp.path().join("proxy.toml");

    let config = format!(
        r#"
[socks5]
listen = "127.0.0.1:{proxy_port}"

[outline]
tcp_ws_url = "{tcp_ws_url}"
tcp_ws_mode = "h3"
udp_ws_url = "{udp_ws_url}"
udp_ws_mode = "h3"
method = "{method}"
password = "{password}"
"#
    );
    fs::write(&config_path, config)?;

    let log_path = temp.path().join("proxy.log");
    let mut proxy = ProxyProcess::start(&config_path, &log_path)?;
    proxy.wait_ready(proxy_port, Duration::from_secs(15))?;

    let (_control, relay_addr) = socks5_udp_associate(proxy_port).map_err(|err| {
        format!(
            "SOCKS5 UDP ASSOCIATE failed: {err}\nproxy logs:\n{}",
            proxy
                .logs()
                .unwrap_or_else(|_| "<proxy logs unavailable>".into())
        )
    })?;

    let client = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    client.set_write_timeout(Some(Duration::from_secs(10)))?;

    let dns_query = build_dns_query(&dns_name)?;
    let packet = build_udp_packet(&dns_server, dns_port, &dns_query)?;
    client.send_to(&packet, relay_addr)?;

    let mut buf = [0u8; 4096];
    let (n, _) = client.recv_from(&mut buf).map_err(|err| {
        format!(
            "failed to receive UDP response: {err}\nproxy logs:\n{}",
            proxy
                .logs()
                .unwrap_or_else(|_| "<proxy logs unavailable>".into())
        )
    })?;

    let response = parse_udp_packet(&buf[..n])?;
    assert_eq!(response.host, dns_server);
    assert_eq!(response.port, dns_port);
    assert!(response.payload.len() >= 12, "DNS response too short");
    assert_eq!(
        &response.payload[..2],
        &dns_query[..2],
        "DNS transaction id mismatch"
    );
    assert!(
        response.payload[3] & 0x0f == 0,
        "DNS response code is non-zero"
    );

    proxy.stop()?;
    Ok(())
}
