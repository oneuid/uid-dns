use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub struct Blocklist {
    domains: HashSet<String>,
}

impl Blocklist {
    pub fn new(custom_path: Option<&str>) -> Self {
        let mut domains = HashSet::new();

        // Seed with default telemetry and malware IOC domains
        let defaults = vec![
            "telemetry.microsoft.com",
            "telemetry.office.com",
            "v10.events.data.microsoft.com",
            "doubleclick.net",
            "google-analytics.com",
            "analytics.google.com",
            "malware-c2.bad",
            "phishing-test.uid",
            "tracking.ads.doubleclick.net",
            "stats.g.doubleclick.net",
            "telemetry.nvidia.com",
            "telemetry.unity3d.com",
        ];

        for d in defaults {
            domains.insert(d.to_string());
        }

        // Load custom file if provided
        if let Some(path_str) = custom_path {
            let path = Path::new(path_str);
            if path.exists() {
                println!("[uid-dns] Loading custom blocklist from: {}", path_str);
                if let Ok(file) = File::open(path) {
                    let reader = BufReader::new(file);
                    let mut count = 0;
                    for line in reader.lines().flatten() {
                        let trimmed = line.trim();
                        // Ignore comments and empty lines
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            domains.insert(trimmed.to_lowercase());
                            count += 1;
                        }
                    }
                    println!("[uid-dns] Loaded {} custom domains.", count);
                }
            } else {
                eprintln!("[uid-dns] Custom blocklist path not found: {}", path_str);
            }
        }

        Self { domains }
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // Exact match
        if self.domains.contains(&domain_lower) {
            return true;
        }

        // Subdomain matching (e.g. tracking.doubleclick.net matches doubleclick.net)
        let parts: Vec<&str> = domain_lower.split('.').collect();
        // Check parts starting from the second element
        // e.g. for a.b.c: checks "b.c", then "c"
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if self.domains.contains(&parent) {
                return true;
            }
        }

        false
    }
}
