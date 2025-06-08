//! Retry operations with exponential backoff strategies
//!
//! This module provides a robust retry mechanism with exponential backoff for handling
//! transient failures in network operations, API calls, and other unreliable operations.
//! Features include:
//!
//! - Configurable retry counts and backoff parameters
//! - Exponential delay between retry attempts
//! - Optional jitter to prevent thundering herd problems
//! - Custom retry condition evaluation
//! - Detailed retry attempt logging
//!
//! The retry logic is designed to work with async operations and integrates with
//! the application's logging system for observability.

use anyhow::Result;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

/// Configuration for the exponential backoff retry strategy
/// 
/// Controls how retry operations are performed, including:
/// - How many retry attempts are made
/// - How long to wait between attempts
/// - How the wait time increases with each attempt
/// - Whether randomization is applied to prevent coordinated retry storms
/// 
/// # Examples
/// 
/// ```
/// use sentri::retry::RetryConfig;
/// 
/// // Default configuration
/// let default_config = RetryConfig::default();
/// 
/// // Custom configuration
/// let custom_config = RetryConfig {
///     max_retries: 5,
///     initial_backoff_ms: 50,
///     backoff_factor: 3.0,
///     max_backoff_ms: 5000,
///     add_jitter: true,
/// };
/// ```
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    
    /// Initial wait time in milliseconds
    pub initial_backoff_ms: u64,
    
    /// Multiplier for each subsequent retry
    pub backoff_factor: f64,
    
    /// Maximum backoff time in milliseconds
    pub max_backoff_ms: u64,
    
    /// Whether to add jitter to backoff times
    pub add_jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 100,
            backoff_factor: 2.0,
            max_backoff_ms: 10000, // 10 seconds
            add_jitter: true,
        }
    }
}

/// Executes a future with exponential backoff retry logic
///
/// Retries the operation if it fails, with exponentially increasing delays
/// between attempts. Can optionally add jitter to prevent thundering herd problems.
/// 
/// This is the core retry function that implements the backoff algorithm and
/// handles the retry logic for all retriable operations in the application.
///
/// # Type Parameters
/// * `F` - Function type that produces a Future
/// * `Fut` - Future type returned by the operation
/// * `T` - Success result type
/// * `E` - Error result type
/// * `R` - Retry predicate function type
///
/// # Arguments
/// * `operation` - An async function that returns a Result
/// * `is_retriable` - A function that determines if an error should trigger a retry
/// * `config` - RetryConfig with backoff parameters
///
/// # Returns
/// * `Result<T, E>` - The successful result of the operation, or the last error if all retries fail
///
/// # Examples
///
/// ```
/// use sentri::retry::{RetryConfig, with_exponential_backoff};
/// use anyhow::Result;
/// 
/// async fn example() -> Result<()> {
///     let config = RetryConfig::default();
///     
///     // Retry an HTTP request with backoff
///     let result = with_exponential_backoff(
///         || async {
///             // Make HTTP request here
///             Ok::<_, anyhow::Error>("success")
///         },
///         |err| {
///             // Determine if error is retriable
///             err.to_string().contains("rate limit")
///         },
///         &config
///     ).await?;
///     
///     Ok(())
/// }
/// ```
pub async fn with_exponential_backoff<F, Fut, T, E, R>(
    operation: F,
    is_retriable: R,
    config: &RetryConfig,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    R: Fn(&E) -> bool,
{
    let mut attempt = 0;
    let mut backoff_ms = config.initial_backoff_ms;
    
    loop {
        let result = operation().await;
        
        match &result {
            Ok(_) => return result,
            Err(err) => {
                attempt += 1;
                
                // If we've reached max retries or the error isn't retriable, return the error
                if attempt >= config.max_retries || !is_retriable(err) {
                    return result;
                }
                
                // Calculate next backoff with optional jitter
                let jitter_ms = if config.add_jitter {
                    let jitter_factor = rand::random::<f64>() * 0.2 + 0.9; // 0.9-1.1 range
                    (backoff_ms as f64 * jitter_factor) as u64
                } else {
                    backoff_ms
                };
                
                // Cap at max backoff time
                let delay = std::cmp::min(jitter_ms, config.max_backoff_ms);
                
                debug!(
                    "Retry attempt {}/{} after {}ms delay", 
                    attempt, 
                    config.max_retries,
                    delay
                );
                
                sleep(Duration::from_millis(delay)).await;
                
                // Calculate next backoff time
                backoff_ms = (backoff_ms as f64 * config.backoff_factor) as u64;
                if backoff_ms > config.max_backoff_ms {
                    backoff_ms = config.max_backoff_ms;
                }
            }
        }
    }
}
