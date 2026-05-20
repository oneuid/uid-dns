use std::time::Duration;

pub fn log_query(client_ip: &str, domain: &str, blocked: bool, duration: Duration) {
    let action = if blocked {
        "\x1b[31mBLOCK\x1b[0m" // Red color for block
    } else {
        "\x1b[32mALLOW\x1b[0m" // Green color for allow
    };

    println!(
        "[uid-dns] {} | Client: {} | Query: {} | Latency: {:?}",
        action, client_ip, domain, duration
    );
}
