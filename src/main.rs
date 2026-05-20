mod config;
mod blocklist;
mod telemetry;
mod resolver;

use crate::config::Config;
use crate::blocklist::Blocklist;
use crate::resolver::Resolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\x1b[1m\x1b[36m====================================================\x1b[0m");
    println!("\x1b[1m\x1b[36m              UID DNS Network Resolver              \x1b[0m");
    println!("\x1b[1m\x1b[36m====================================================\x1b[0m");

    // Load configuration from command line / environment
    let config = Config::load();

    // Load blocklist
    let blocklist = Blocklist::new(config.blocklist_path.as_deref());

    // Create and run resolver
    let resolver = Resolver::new(config, blocklist);
    resolver.run().await?;

    Ok(())
}
