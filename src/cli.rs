//! Command-line interface for Sentri MDI discovery tool
//!
//! This module provides a robust and secure command-line interface for Microsoft Defender
//! for Identity (MDI) discovery operations using the clap framework, featuring:
//!
//! - Command-line argument parsing with comprehensive validation
//! - Subcommand support for different operation modes with consistent interfaces
//! - Security-focused parameter validation and input sanitization
//! - Configurable concurrency, rate limiting, and timeout settings
//! - Detailed help documentation and version information
//! - Memory-efficient batch processing for large domain lists
//! - Proper resource management for I/O operations
//!
//! # Security Considerations
//!
//! This module implements several security best practices:
//!
//! - **Input Validation**: All domain parameters are validated through the validation module
//!   to prevent injection attacks and ensure RFC compliance (security:input:sanitize_all_input)
//! - **Rate Limiting**: Configurable rate limiting prevents API abuse and respects Microsoft's
//!   service limits (mdi:api:respect_api_limits)
//! - **Timeout Controls**: All network operations have configurable timeouts to prevent resource
//!   exhaustion (security:network:timeout_all_requests)
//! - **Path Handling**: Secure handling of file paths with proper access validation and error
//!   messaging
//! - **Error Information Control**: Balances error details with security to prevent sensitive
//!   information leakage (security:output:error_info_control)
//! - **Suspicious Domain Detection**: Leverages validation module's heuristic detection for
//!   potentially malicious domains
//!
//! # Performance Optimizations
//!
//! - **Streaming I/O**: Uses streaming for file operations to efficiently handle large files
//!   without excessive memory consumption (performance:memory:use_streaming_io)
//! - **Configurable Concurrency**: Allows tuning parallelism based on available system
//!   resources and API rate limits (concurrency:use_semaphores_for_concurrency_limits)
//! - **Memory Management**: Processes large input files in chunks to control memory usage
//!   (performance:memory:avoid_unnecessary_allocations)
//! - **Connection Pooling**: Leverages HTTP client's connection pooling for efficient
//!   network resource usage (performance:http_client:connection_pooling_required)
//! - **Backoff Strategy**: Integrates with retry module to implement exponential backoff
//!   with jitter for failed requests (mdi:domains:retry_with_backoff)
//!
//! # Usage Modes
//!
//! The CLI supports two primary operation modes:
//!
//! - **Single Domain**: Interactive checking of individual domains with detailed output
//! - **Batch Processing**: High-volume operations with parallelism controls, optimized for
//!   processing thousands of domains efficiently
//!
//! # Error Handling
//!
//! Error handling follows Rust best practices for robust operation:
//!
//! - Detailed error messages with proper context for better troubleshooting
//!   (rust:errors:proper_error_context)
//! - Standard exit codes (0 for success, non-zero for failures)
//! - Error categorization to distinguish between configuration errors, network failures,
//!   and data validation issues
//! - Propagation of underlying error information without leaking sensitive details

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Main command-line interface structure for Sentri
///
/// The CLI uses the clap framework for robust command-line parsing and provides
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
/// and should be tuned based on available system resources and external API rate limits:
///
/// - **Optimal Concurrency**: Starting with 100 concurrent requests provides a good
///   balance between throughput and resource usage on most systems. Monitor system
///   resource utilization and adjust as needed (performance:concurrency:limit_tokio_worker_threads).
///
/// - **Memory Impact**: Each concurrent request requires memory for connection state,
///   buffers, and temporary results. For resource-constrained environments, consider
///   reducing concurrency (performance:memory:avoid_unnecessary_allocations).
///
/// - **API Rate Limiting**: Microsoft API endpoints may enforce rate limiting. If you
///   receive HTTP 429 responses, reduce the concurrency setting and/or implement
///   progressive backoff (mdi:api:respect_api_limits).
///
/// The `timeout_ms` parameter significantly affects reliability and throughput:
///
/// - **Network Variability**: Default timeout is tuned for typical network conditions.
///   For high-latency networks, consider increasing the value to at least 10000ms
///   (security:network:timeout_all_requests).
///
/// - **Throughput Impact**: Shorter timeouts increase overall throughput but may
///   lead to more false negatives. For critical scanning, use longer timeouts
///   (e.g., 8000-10000ms) (mdi:domains:retry_with_backoff).
///
/// - **Resource Management**: Every request consumes a connection until completion
///   or timeout. Setting appropriate timeouts prevents resource exhaustion
///   (concurrency:avoid_blocking_in_async).
///
/// # Security Considerations
///
/// This struct implements several security best practices:
///
/// - **Input Validation**: All domain inputs undergo strict RFC-compliant validation
///   through the validation module before processing. This prevents injection attacks
///   and malformed inputs (security:input:sanitize_all_input).
///
/// - **Suspicious Domain Detection**: The validation module includes heuristic-based
///   detection for potentially malicious domains including homograph attacks and
///   patterns associated with phishing campaigns (security:input:validate_domain_names).
///
/// - **Controlled Error Information**: Error messages provide sufficient context for
///   troubleshooting without revealing sensitive implementation details
///   (security:output:error_info_control).
///
/// - **Resource Limits**: Default settings prevent resource exhaustion attacks by
///   limiting concurrent operations and implementing timeouts on all network requests
///   (security:input:limit_input_size).
///
/// # Examples
///
/// ## Basic usage parsing command line arguments
///
/// ```no_run
/// use sentri::cli::Cli;
/// use clap::Parser;
///
/// // Parse command line arguments
/// let cli = Cli::parse();
///
/// // Access configuration values
/// println!("Using {} concurrent requests", cli.concurrent_requests);
/// println!("Request timeout set to {}ms", cli.timeout_ms);
/// ```
///
/// ## Creating a CLI instance programmatically
///
/// ```no_run
/// use sentri::cli::{Cli, Commands};
/// use std::path::PathBuf;
/// use std::time::Duration;
///
/// // Create a batch processing configuration with custom settings
/// let cli_struct = Cli {
///     command: Commands::Batch {
///         input_file: PathBuf::from("/path/to/domains.txt"),
///         output_file: Some(PathBuf::from("/path/to/results.json")),
///         chunk_size: 500,
///         rate_limit: 30,
///     },
///     concurrent_requests: 50,
///     timeout_ms: 8000,
/// };
///
/// // These values would typically be passed to your core processing logic
/// let timeout = Duration::from_millis(cli_struct.timeout_ms);
/// let concurrency = cli_struct.concurrent_requests;
/// ```
///
/// ## Configuring for various network environments
///
/// ```no_run
/// use sentri::cli::Cli;
/// use clap::Parser;
///
/// // For high-latency networks, use longer timeouts and reduced concurrency
/// let args = vec![
///     "sentri", "batch",
///     "--input-file", "domains.txt",
///     "--timeout-ms", "10000",
///     "--concurrent-requests", "25",
///     "--rate-limit", "20"
/// ];
///
/// // Parse would use the provided arguments in a real application
/// // Here we're just demonstrating the configuration pattern
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
/// The tool supports two primary modes of operation, each optimized for different use cases:
/// - `Single`: Checking a single domain interactively with detailed output
/// - `Batch`: Processing multiple domains from a file with configurable parallelism and rate limiting
///
/// # Implementation Details
///
/// Both commands share the same core DNS resolution and autodiscover logic, but differ in:
/// - I/O handling (interactive vs file-based)
/// - Output formatting (human-readable vs structured JSON)
/// - Resource management (single request vs configurable parallelism)
/// - Error handling approaches (immediate vs aggregated reporting)
///
/// # Security Considerations
///
/// - **Input Validation**: Both commands apply strict validation to domain inputs
///   to prevent injection attacks and invalid formats (security:input:sanitize_all_input)
/// - **Rate Limiting**: The batch command includes explicit rate limiting to prevent
///   API abuse and comply with service limits (mdi:api:respect_api_limits)
/// - **Resource Protection**: File operations include proper error handling to prevent
///   resource exhaustion from large files (performance:memory:use_streaming_io)
/// - **Access Controls**: File paths are properly validated to prevent unauthorized
///   access outside permitted directories
///
/// # Performance Optimizations
///
/// - **Memory Efficiency**: The batch command processes files in configurable chunks
///   to control memory usage for large input files (performance:memory:avoid_unnecessary_allocations)
/// - **Concurrency Control**: Batch processing uses semaphores to limit concurrent operations
///   based on available system resources (concurrency:use_semaphores_for_concurrency_limits)
/// - **Connection Reuse**: Both commands leverage connection pooling from the HTTP client
///   for efficient network resource usage (performance:http_client:connection_pooling_required)
/// - **Output Buffering**: The batch command implements efficient output writing with
///   buffered I/O to reduce system calls
///
/// # Examples
///
/// ## Single domain check with timeout configuration:
/// ```text
/// sentri single --domain example.com --timeout-ms 8000 --concurrent-requests 10
/// ```
///
/// ## Batch processing with full configuration:
/// ```text
/// sentri batch \
///   --input-file domains.txt \
///   --output-file results.json \
///   --rate-limit 30 \
///   --chunk-size 500 \
///   --concurrent-requests 25 \
///   --timeout-ms 5000
/// ```
///
/// ## Batch processing with defaults (stdout output):
/// ```text
/// sentri batch --input-file domains.txt
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
