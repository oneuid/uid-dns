# UID DNS

UID DNS is a high-performance, Rust-based DoH/DoT network resolver for the UID.one ecosystem, focusing on proactive threat interception and zero-config IoT security.

For detailed architectural specifications, please see the [UID 7-Layer Architecture](../uid-web/docs/uid-architecture-7-layers.md).

## Prerequisites
- [Rust](https://rustup.rs/) (1.75+)
- Cargo

## Getting Started

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd uid-dns
   ```

2. **Build the project**
   ```bash
   cargo build --release
   ```

3. **Run the server**
   ```bash
   cargo run
   ```

## Development
- `src/main.rs`: Application entry point.
- Ensure to run `cargo fmt` and `cargo clippy` before submitting pull requests.

## License

This project is licensed under the [Apache License 2.0](LICENSE). 

By open-sourcing our client-side network components, we ensure complete transparency in how DNS requests and threat intelligence are handled. We welcome community audits and contributions.
