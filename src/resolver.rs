use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::blocklist::Blocklist;
use crate::config::Config;
use crate::telemetry;

pub struct Resolver {
    config: Arc<Config>,
    blocklist: Arc<Blocklist>,
}

impl Resolver {
    pub fn new(config: Config, blocklist: Blocklist) -> Self {
        Self {
            config: Arc::new(config),
            blocklist: Arc::new(blocklist),
        }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(&self.config.listen_addr).await?;
        println!(
            "[uid-dns] Network Gateway DNS listening on {}",
            self.config.listen_addr
        );
        println!(
            "[uid-dns] Upstream resolver configured: {}",
            self.config.upstream_addr
        );

        let shared_socket = Arc::new(socket);

        loop {
            let mut buf = vec![0u8; 4096];
            let socket_clone = shared_socket.clone();
            let config_clone = self.config.clone();
            let blocklist_clone = self.blocklist.clone();

            match shared_socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    buf.truncate(len);
                    tokio::spawn(async move {
                        let start_time = Instant::now();
                        
                        if let Some(domain) = parse_qname(&buf) {
                            let is_blocked = blocklist_clone.is_blocked(&domain);
                            
                            if is_blocked {
                                // Construct NXDOMAIN response (RCODE = 3)
                                let response = construct_error_response(&buf, 3);
                                if let Err(e) = socket_clone.send_to(&response, src).await {
                                    eprintln!("[uid-dns] Error sending block response: {:?}", e);
                                }
                                telemetry::log_query(&src.to_string(), &domain, true, start_time.elapsed());
                            } else {
                                // Proxy to upstream
                                match proxy_query(&buf, &config_clone.upstream_addr).await {
                                    Ok(response) => {
                                        if let Err(e) = socket_clone.send_to(&response, src).await {
                                            eprintln!("[uid-dns] Error sending proxy response: {:?}", e);
                                        }
                                        telemetry::log_query(&src.to_string(), &domain, false, start_time.elapsed());
                                    }
                                    Err(_) => {
                                        // Send SERVFAIL (RCODE = 2) on error or timeout
                                        let response = construct_error_response(&buf, 2);
                                        let _ = socket_clone.send_to(&response, src).await;
                                        telemetry::log_query(&src.to_string(), &domain, false, start_time.elapsed());
                                    }
                                }
                            }
                        } else {
                            // Forward query directly even if QNAME parsing fails (fall-through support)
                            match proxy_query(&buf, &config_clone.upstream_addr).await {
                                Ok(response) => {
                                    let _ = socket_clone.send_to(&response, src).await;
                                }
                                Err(_) => {
                                    let response = construct_error_response(&buf, 2);
                                    let _ = socket_clone.send_to(&response, src).await;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[uid-dns] UDP Socket recv error: {:?}", e);
                }
            }
        }
    }
}

async fn proxy_query(query: &[u8], upstream_addr: &str) -> Result<Vec<u8>, std::io::Error> {
    // Bind dynamic local UDP socket
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
    upstream_socket.send_to(query, upstream_addr).await?;

    let mut resp_buf = vec![0u8; 4096];
    
    // Set 2-second timeout for upstream response to keep DNS fast
    let (resp_len, _) = timeout(
        Duration::from_secs(2),
        upstream_socket.recv_from(&mut resp_buf),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Upstream timeout"))??;

    resp_buf.truncate(resp_len);
    Ok(resp_buf)
}

fn parse_qname(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }
    let mut cursor = 12;
    let mut domain = String::new();
    
    loop {
        if cursor >= packet.len() {
            return None;
        }
        let len = packet[cursor] as usize;
        if len == 0 {
            break;
        }
        // Handle compression pointer check
        if len & 0xC0 == 0xC0 {
            return None;
        }
        if cursor + 1 + len > packet.len() {
            return None;
        }
        if !domain.is_empty() {
            domain.push('.');
        }
        let label = std::str::from_utf8(&packet[cursor + 1..cursor + 1 + len]).ok()?;
        domain.push_str(label);
        cursor += 1 + len;
    }
    
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn construct_error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut response = query.to_vec();
    if response.len() < 12 {
        return response;
    }
    
    // Set QR = 1 (Response), AA = 1 (Authoritative Answer)
    let mut flags = u16::from_be_bytes([response[2], response[3]]);
    flags |= 0x8400; // Set QR, AA
    flags &= 0xFFF0; // Clear RCODE
    flags |= rcode as u16; // Set target RCODE (2 for SERVFAIL, 3 for NXDOMAIN)
    
    let flags_bytes = flags.to_be_bytes();
    response[2] = flags_bytes[0];
    response[3] = flags_bytes[1];
    
    // Set Answer, Authority and Additional RR counts to 0
    response[6] = 0; response[7] = 0; // ANCOUNT
    response[8] = 0; response[9] = 0; // NSCOUNT
    response[10] = 0; response[11] = 0; // ARCOUNT
    
    response
}
