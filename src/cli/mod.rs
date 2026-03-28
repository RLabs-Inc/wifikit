pub mod app;
pub mod module;
pub mod banner;
pub mod commands;
pub mod views;
pub mod scanner;

use crate::core::Result;

/// Entry point for the CLI application.
pub fn run() -> Result<()> {
    let verbose = std::env::args().any(|a| a == "-v" || a == "--verbose");
    app::run(verbose)
}
