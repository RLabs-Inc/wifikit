mod core;
mod chips;
mod protocol;
mod util;
mod engine;
mod store;
mod pipeline;
mod adapter;
mod scanner;
mod attacks;
mod cli;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Detect adapters only: `wifikit --detect`
    if args.iter().any(|a| a == "--detect") {
        match core::adapter::scan_adapters() {
            Ok(adapters) => {
                println!("Found {} adapter(s):", adapters.len());
                for (i, info) in adapters.iter().enumerate() {
                    println!("  [{}] {} (VID={:#06x} PID={:#06x} chip={} bus={} addr={})",
                        i + 1, info.name, info.vid, info.pid, info.chip, info.bus, info.address);
                }
                if adapters.is_empty() {
                    println!("  No supported adapters found.");
                }
            }
            Err(e) => {
                eprintln!("USB scan failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Err(e) = cli::run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
