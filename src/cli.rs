//! Command-line interface for Sentri MDI discovery tool
//!
//! This module provides a robust command-line interface for Microsoft Defender for Identity (MDI)
//! discovery operations using the clap framework, featuring:
//!
//! - Command-line argument parsing with validation
//! - Subcommand support for different operation modes
//! - Security-focused parameter validation and sanitization
//! - Configurable concurrency, rate limiting, and timeout settings
//! - Detailed help documentation and version information
//!
//! # Security Features
//!
//! - Input validation for all domain parameters through the validation module
//! - Rate limiting to prevent API abuse and respect Microsoft's limits
//! - Timeout settings to prevent hanging connections
//! - Secure handling of file paths with proper error messaging
//!
//! # Usage Modes
//!
//! The CLI supports two primary operation modes:
//! - Single domain checking for interactive use
//! - Batch processing for high-volume operations with parallelism controls
//!
//! # Error Handling
//!
//! Error messages are presented with context for better troubleshooting
//! and exit codes follow standard conventions (0 for success, non-zero for failures).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Main command-line interface structure for Sentri
///
/// The CLI uses clap for robust command-line parsing and provides
/// a subcommand-based interface for different operations. Global options
/// like concurrency and timeout settings apply to all subcommands.
/// 
/// # Fields
/// 
/// * `command` - The subcommand to execute (Single or Batch)
/// * `concurrent_requests` - Number of parallel operations allowed
/// * `timeout_ms` - HTTP request timeout in milliseconds
/// 
/// # Performance Considerations
/// 
/// The `concurrent_requests` parameter directly controls the degree of parallelism
/// and should be tuned based on system resources and API rate limits. Setting this
/// too high may trigger rate limiting or exhaust system resources.
/// 
/// The `timeout_ms` parameter should be set based on expected network conditions.
/// Too short timeouts may cause false negatives for slow-responding domains,
/// while too long timeouts can reduce overall throughput.
/// 
/// # Security
/// 
/// All domain inputs are validated through the validation module which implements
/// RFC-compliant domain validation and suspicious domain detection to prevent
/// security issues.
///
/// # Examples
///
/// ```no_run
/// use sentri::cli::Cli;
/// use clap::Parser;
/// use std::env;
///
/// // In a real application, you'd parse from command-line args
/// // Here we're just showing the structure without trying to parse
/// let cli_struct = Cli {
///     command: sentri::cli::Commands::Single { 
///         domain: "example.com".to_string() 
///     },
///     concurrent_requests: 50,
///     timeout_ms: 3000,
/// };
///
/// // Access configuration
/// println!("Using {} concurrent requests", cli_struct.concurrent_requests);
/// println!("Timeout set to {} ms", cli_struct.timeout_ms);
/// ```
#[derive(Parser)]
#[command(
    name = "sentri",
    about = "High-performance Microsoft Defender for Identity instance discovery tool",
    version
)]
pub struct Cli {
    /// Command to execute (single domain check or batch processing)
    #[command(subcommand)]
    pub command: Commands,

    /// Number of concurrent requests for parallel processing
    /// Higher values increase throughput but may trigger rate limiting
    #[arg(short = 'c', long, default_value = "100")]
    pub concurrent_requests: usize,

    /// Request timeout in milliseconds for HTTP operations
    /// Increase this value when checking slow-responding domains
    #[arg(short = 't', long, default_value = "5000")]
    pub timeout_ms: u64,
}

/// Available subcommands for the Sentri CLI
///
/// The tool supports two primary modes of operation:
/// - `Single`: Checking a single domain interactively
/// - `Batch`: Processing multiple domains from a file with configurable parallelism
///
/// # Examples
///
/// Single domain check:
/// ```text
/// sentri single --domain example.com
/// ```
///
/// Batch processing:
/// ```text
/// sentri batch --input-file domains.txt --output-file results.json --rate-limit 30
/// ```
#[derive(Subcommand)]
pub enum Commands {
    /// Check a single domain for MDI presence
    ///
    /// Performs a comprehensive check on one domain, including:
    /// - Federation information retrieval
    /// - Tenant identification
    /// - MDI instance detection
    ///
    /// Results are displayed in a detailed format to stdout.
    Single {
        /// Domain to check (e.g., example.com)
        #[arg(short, long)]
        domain: String,
    },
    /// Process multiple domains from file with parallel execution
    ///
    /// This mode reads domains from a file (one per line) and processes
    /// them in parallel with configurable rate limiting. Results can be
    /// output to stdout or written to a file in JSONL format (one JSON
    /// object per line).
    ///
    /// Empty lines and those starting with '#' in the input file are skipped.
    Batch {
        /// Input file containing domains (one per line)
        #[arg(short, long)]
        input_file: PathBuf,

        /// Output file for results (JSON format, one result per line)
        /// If not specified, results are printed to stdout
        #[arg(short, long)]
        output_file: Option<PathBuf>,

        /// Chunk size for batch processing
        /// Controls memory usage and output frequency
        #[arg(long, default_value = "1000")]
        chunk_size: usize,

        /// Rate limit (requests per minute)
        /// Adjust to comply with Microsoft API rate limits
        #[arg(short, long, default_value = "50")]
        rate_limit: u64,
    },
}