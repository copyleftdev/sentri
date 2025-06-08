use clap::Parser;
use anyhow::Result;

use tracing::{info, debug};
use tokio::runtime::Builder;

mod cli;
mod core;
mod dns;
mod http;
mod xml;
mod validation;
mod retry;
mod rate_limit;

use cli::Cli;
use core::MdiChecker;

fn main() -> Result<()> {
    // Configure Tokio runtime with appropriate worker threads
    // This follows the rule limit_tokio_worker_threads from .windsurfrules
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    // Limit maximum worker threads to avoid excessive resource usage
    // Use available_parallelism but cap it at 16 to prevent excessive context switching
    // For IO-heavy workloads like network requests, slightly more threads than cores can be beneficial
    let worker_threads = std::cmp::min(num_cpus + 2, 16);
    
    debug!("Configuring Tokio runtime with {} worker threads", worker_threads);
    
    let runtime = Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    // Run our async main function in the configured runtime
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let checker = MdiChecker::new(cli.concurrent_requests, cli.timeout_ms)?;

    match &cli.command {
        cli::Commands::Single { domain } => {
            info!("Checking single domain: {}", domain);
            let result = checker.check_domain(domain).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        cli::Commands::Batch { 
            input_file, 
            output_file, 
            chunk_size,
            rate_limit 
        } => {
            info!("Processing batch from file: {:?}", input_file);
            checker.process_batch(
                input_file, 
                output_file.as_ref(), 
                *chunk_size, 
                *rate_limit
            ).await?;
        }
    }

    Ok(())
}