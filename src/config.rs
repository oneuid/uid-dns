use std::env;

pub struct Config {
    pub listen_addr: String,
    pub upstream_addr: String,
    pub blocklist_path: Option<String>,
}

impl Config {
    pub fn load() -> Self {
        let args: Vec<String> = env::args().collect();
        
        let mut listen_port = "5353".to_string(); // default non-privileged port
        let mut upstream_addr = "1.1.1.1:53".to_string(); // default Cloudflare DNS
        let mut blocklist_path = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--port" | "-p" if i + 1 < args.len() => {
                    listen_port = args[i + 1].clone();
                    i += 2;
                }
                "--upstream" | "-u" if i + 1 < args.len() => {
                    upstream_addr = args[i + 1].clone();
                    i += 2;
                }
                "--blocklist" | "-b" if i + 1 < args.len() => {
                    blocklist_path = Some(args[i + 1].clone());
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }

        let listen_addr = format!("0.0.0.0:{}", listen_port);

        Self {
            listen_addr,
            upstream_addr,
            blocklist_path,
        }
    }
}
