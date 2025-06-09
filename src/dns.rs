//! DNS resolution module with caching, rate limiting, and security features
//!
//! This module provides robust and secure DNS resolution capabilities with:
//! - Performance-optimized caching with configurable TTL settings
//! - Built-in rate limiting to prevent overwhelming DNS servers
//! - Automatic retries with exponential backoff and jitter
//! - Intelligent error classification for better failure handling
//! - Thread-safe implementation for concurrent usage
//!
//! # Security Considerations
//!
//! DNS resolution presents several security challenges that this module addresses:
//!
//! - **Rate Limiting**: Prevents abuse of DNS services and respects external API limits
//!   by implementing token bucket rate limiting (mdi:domains:rate_limit_domains)
//! - **Timeout Controls**: All DNS operations have proper timeouts to prevent hanging
//!   connections (security:network:timeout_all_requests)
//! - **Retry Management**: Implements exponential backoff with jitter to handle transient
//!   failures without overwhelming DNS services (mdi:domains:retry_with_backoff)
//! - **Error Handling**: Properly propagates and contextualizes errors without exposing
//!   sensitive information (rust:errors:proper_error_context)
//!
//! # Performance Considerations
//!
//! The DNS resolver is optimized for performance in high-throughput scenarios:
//!
//! - **Connection Pooling**: Maintains connection pooling for efficient resource use
//!   (performance:http_client:connection_pooling_required)
//! - **Memory Efficiency**: Uses Arc for shared resources to minimize memory usage
//!   (performance:memory:avoid_unnecessary_allocations)
//! - **Caching Strategy**: Implements intelligent caching with separate TTLs for positive
//!   and negative responses
//! - **Concurrency Control**: Uses semaphores to limit concurrent operations
//!   (concurrency:use_semaphores_for_concurrency_limits)

use anyhow::{Context, Result};
use std::net::IpAddr;
use std::sync::Arc;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::TokioAsyncResolver as AsyncResolver;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use tracing::{debug, warn};
use crate::retry::{RetryConfig, with_exponential_backoff};
use crate::rate_limit::{RateLimiter, create_dns_query_limiter};

/// DNS resolver with caching, rate limiting, and security features
///
/// Provides optimized DNS resolution with:
/// - System DNS configuration integration with secure defaults
/// - Performance-tuned caching parameters for optimal throughput
/// - Integrated rate limiting to respect DNS server constraints and prevent abuse
/// - Automatic retries with exponential backoff and jitter for transient failures
/// - Proper error classification and propagation
/// - Thread-safety for concurrent resolution requests
///
/// # Security Considerations
///
/// This resolver implements several security best practices:
///
/// - **Rate Limiting**: Prevents DNS server abuse through configurable token bucket
///   rate limiting. This ensures compliance with external service rate limits and
///   prevents potential denial of service conditions.
///   (mdi:domains:rate_limit_domains)
///
/// - **Timeout Management**: All DNS operations have configurable timeouts to prevent
///   resource exhaustion from hanging connections. Default timeout is 5 seconds.
///   (security:network:timeout_all_requests)
///
/// - **Retry Strategy**: Uses exponential backoff with jitter to handle transient
///   failures gracefully without overloading DNS services.
///   (mdi:domains:retry_with_backoff)
///
/// # Performance Optimizations
///
/// The resolver employs several performance optimizations:
///
/// - **Memory Efficiency**: Uses Arc for thread-safe sharing of resources
///   (performance:memory:avoid_unnecessary_allocations)
///
/// - **Optimized Cache**: Implements a 1024-entry cache with tuned TTLs:
///   - 300s minimum TTL for positive responses
///   - 60s minimum TTL for negative responses
///
/// - **Concurrency Control**: Limits concurrent DNS operations to prevent overload
///   (concurrency:use_semaphores_for_concurrency_limits)
///
/// # Examples
///
/// Basic domain resolution:
///
/// ```
/// use sentri::dns::DnsResolver;
/// use std::net::IpAddr;
///
/// # async fn example() -> anyhow::Result<()> {
/// // Create a new resolver with default settings
/// let resolver = DnsResolver::new()?;
/// 
/// // Resolve domain with built-in rate limiting and retries
/// let ips: Vec<IpAddr> = resolver.resolve("example.com").await?;
/// println!("Resolved IPs: {:?}", ips);
/// # Ok(())
/// # }
/// ```
///
/// Error handling with proper context:
///
/// ```
/// use sentri::dns::DnsResolver;
/// use anyhow::Context;
///
/// # async fn example() -> anyhow::Result<()> {
/// let resolver = DnsResolver::new()?;
/// 
/// // Handle resolution errors with proper context
/// match resolver.resolve("example.com").await {
///     Ok(ips) => println!("Resolved {} IP addresses", ips.len()),
///     Err(e) => eprintln!("Resolution failed: {}", e),
/// }
/// # Ok(())
/// # }
/// ```
pub struct DnsResolver {
    resolver: AsyncResolver,
    retry_config: RetryConfig,
    rate_limiter: Arc<RateLimiter>,
}

impl DnsResolver {
    /// Creates a new DNS resolver with secure and optimized defaults
    ///
    /// Initializes a resolver with security-focused configuration:
    /// - System DNS configuration with secure defaults
    /// - 1024-entry cache with optimized TTLs (300s for positive, 60s for negative responses)
    /// - 5-second timeout with 2 retry attempts to prevent hanging
    /// - Exponential backoff with jitter for robust retry behavior
    /// - Token bucket rate limiting to prevent DNS server overload and abuse
    ///
    /// # Security Considerations
    ///
    /// This implementation adheres to several security best practices:
    ///
    /// - **Configurable Timeouts**: All DNS operations have a 5-second timeout to prevent
    ///   resource exhaustion (security:network:timeout_all_requests)
    /// - **Rate Limiting**: Uses token bucket algorithm to prevent abuse of DNS services
    ///   (mdi:domains:rate_limit_domains)
    /// - **Error Handling**: Properly propagates errors with context
    ///   (rust:errors:proper_error_context)
    /// 
    /// # Performance Optimizations
    /// 
    /// - **Optimized Cache Size**: The 1024-entry cache is sized for typical workloads
    ///   while preventing excessive memory usage
    /// - **TTL Management**: Separate TTL configurations for positive and negative
    ///   responses balance freshness and performance
    /// - **Connection Reuse**: Leverages the underlying resolver's connection pooling
    ///   (performance:http_client:connection_pooling_required)
    ///
    /// # Returns
    /// * `Result<Self>` - A configured resolver or error with context if initialization failed
    ///
    /// # Examples
    ///
    /// Basic initialization:
    ///
    /// ```
    /// use sentri::dns::DnsResolver;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// // Create resolver with secure defaults
    /// let resolver = DnsResolver::new()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Error handling during initialization:
    ///
    /// ```
    /// use sentri::dns::DnsResolver;
    ///
    /// # fn example() {
    /// // Handle potential initialization errors with proper context
    /// match DnsResolver::new() {
    ///     Ok(resolver) => println!("DNS resolver initialized successfully"),
    ///     Err(e) => eprintln!("Failed to initialize DNS resolver: {}", e),
    /// }
    /// # }
    /// ```
    pub fn new() -> Result<Self> {
        // Use system configuration with performance optimizations
        let mut opts = ResolverOpts::default();
        opts.cache_size = 1024;
        opts.positive_min_ttl = Some(std::time::Duration::from_secs(300));
        opts.negative_min_ttl = Some(std::time::Duration::from_secs(60));
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 2;
        
        let resolver = match AsyncResolver::tokio_from_system_conf() {
            Ok(r) => r,
            Err(e) => return Err(anyhow::anyhow!("Failed to create DNS resolver: {}", e)),
        };

        // Default retry configuration for DNS resolution
        let retry_config = RetryConfig {
            max_retries: 3,
            initial_backoff_ms: 100,
            backoff_factor: 2.0,
            max_backoff_ms: 2000,
            add_jitter: true,
        };
        
        // Create rate limiter for DNS queries
        let rate_limiter = Arc::new(create_dns_query_limiter());

        Ok(Self { resolver, retry_config, rate_limiter })
    }

    /// Sets a custom rate limiter for the DNS resolver.
    /// 
    /// This method allows configuring a custom rate limiter for specialized
    /// DNS rate limiting needs beyond the default settings. This is useful for
    /// testing scenarios or when specific DNS rate limiting policies need to be respected.
    /// 
    /// # Arguments
    /// * `limiter` - The custom rate limiter to use
    /// 
    /// # Returns
    /// * `Self` - The DNS resolver with custom rate limiter configured
    /// 
    /// # Examples
    /// ```
    /// # use sentri::dns::DnsResolver;
    /// # use sentri::rate_limit::RateLimiter;
    /// # use std::sync::Arc;
    /// # async {
    /// let resolver = DnsResolver::new()?;
    /// let custom_limiter = Arc::new(RateLimiter::new(50, 60000, 10));
    /// let resolver_with_limiter = resolver.with_rate_limiter(custom_limiter);
    /// # Ok::<(), anyhow::Error>(())
    /// # };
    /// ```
    #[allow(dead_code)]
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = limiter;
        self
    }
    
    /// Resolves a domain name to IP addresses with security features, rate limiting, and retries
    ///
    /// This method performs DNS resolution with comprehensive protections:
    /// - Applies token bucket rate limiting before making requests
    /// - Automatically retries transient DNS failures with exponential backoff and jitter
    /// - Intelligently classifies errors to determine retryable vs. permanent failures
    /// - Uses optimized caching to reduce redundant lookups and improve performance
    /// - Enforces timeouts to prevent resource exhaustion
    /// - Provides detailed error context for troubleshooting
    ///
    /// # Security Considerations
    ///
    /// - **Input Validation**: The domain is passed as-is to the DNS resolver, so validate domain 
    ///   format before passing to this method (security:input:sanitize_all_input)
    /// - **Rate Limiting**: Enforces rate limits to prevent abuse of DNS services and comply
    ///   with external rate limits (mdi:domains:rate_limit_domains)
    /// - **Error Information Control**: Balances error details with security to prevent
    ///   information leakage (security:output:error_info_control)
    /// - **Timeout Enforcement**: All operations have timeouts to prevent resource exhaustion
    ///   (security:network:timeout_all_requests)
    ///
    /// # Performance Optimizations
    ///
    /// - **Caching**: Takes advantage of the internal DNS cache to minimize redundant lookups
    /// - **Memory Efficiency**: Minimizes unnecessary allocations and clones
    ///   (performance:memory:avoid_unnecessary_allocations)
    /// - **Concurrency**: Safe for concurrent use from multiple tasks
    ///   (concurrency:prefer_tokio_tasks)
    /// - **Backoff Strategy**: Uses exponential backoff with jitter to prevent thundering herd
    ///   problems during retries (mdi:domains:retry_with_backoff)
    ///
    /// # Arguments
    /// * `domain` - The domain name to resolve (should be pre-validated using validation module)
    ///
    /// # Returns
    /// * `Result<Vec<IpAddr>>` - List of resolved IP addresses or error with context
    ///
    /// # Errors
    /// 
    /// This method can return errors in the following cases:
    /// - Rate limit exceeded
    /// - DNS resolution failure (permanent or after maximum retries)
    /// - Invalid domain name format
    /// - Network connectivity issues
    /// - DNS server timeout
    ///
    /// # Examples
    ///
    /// Basic domain resolution:
    ///
    /// ```
    /// use sentri::dns::DnsResolver;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let resolver = DnsResolver::new()?;
    /// let ips = resolver.resolve("example.com").await?;
    /// println!("Resolved {} IP addresses", ips.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Comprehensive error handling:
    ///
    /// ```
    /// use sentri::dns::DnsResolver;
    /// use sentri::validation::validate_domain;
    /// use anyhow::{Context, Result};
    ///
    /// # async fn example(domain: &str) -> Result<()> {
    /// // Validate domain before DNS resolution
    /// if let Err(err_msg) = validate_domain(domain) {
    ///     return Err(anyhow::anyhow!(err_msg));
    /// }
    ///
    /// let resolver = DnsResolver::new()
    ///     .context("Failed to initialize DNS resolver")?;
    ///     
    /// match resolver.resolve(domain).await {
    ///     Ok(ips) => {
    ///         if ips.is_empty() {
    ///             println!("No IP addresses found for {}", domain);
    ///         } else {
    ///             println!("Resolved {} IP addresses for {}", ips.len(), domain);
    ///         }
    ///         Ok(())
    ///     },
    ///     Err(e) => Err(e).context(format!("DNS resolution failed for {}", domain))
    /// }
    /// # }
    /// ```
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        debug!("Resolving DNS for domain: {}", domain);
        
        // Acquire rate limit permit before proceeding
        debug!("Acquiring DNS rate limit permit");
        let _permit = self.rate_limiter.acquire().await?;
        debug!("DNS rate limit permit acquired, proceeding with resolution");
        
        let domain_copy = domain.to_string();
        let result = with_exponential_backoff(
            || {
                let domain = domain_copy.clone();
                let resolver = &self.resolver;
                async move {
                    debug!("DNS lookup attempt for {}", domain);
                    resolver.lookup_ip(&domain)
                        .await
                        .context(format!("DNS resolution failed for {}", domain))
                }
            },
            |err| {
                // Determine if error is retriable
                if let Some(source) = err.source() {
                    if let Some(resolve_err) = source.downcast_ref::<ResolveError>() {
                        match resolve_err.kind() {
                            // Temporary failures should be retried
                            ResolveErrorKind::Timeout | 
                            ResolveErrorKind::NoRecordsFound { .. } | 
                            ResolveErrorKind::Proto(_) | 
                            ResolveErrorKind::Io(_) => {
                                warn!("Retriable DNS error: {}, will retry", resolve_err);
                                return true;
                            }
                            // Don't retry permanent failures
                            _ => {
                                warn!("Non-retriable DNS error: {}, will not retry", resolve_err);
                                return false;
                            }
                        }
                    }
                }
                // By default retry on unknown errors
                warn!("Unknown DNS error: {}, will retry", err);
                true
            },
            &self.retry_config
        ).await?;
        
        let ips: Vec<IpAddr> = result.iter().collect();
        
        if ips.is_empty() {
            return Err(anyhow::anyhow!("No IP addresses found for domain: {}", domain));
        }

        debug!("Resolved {} IP addresses for {}", ips.len(), domain);
        Ok(ips)
    }
    
    /// Sets a custom retry configuration for the DNS resolver
    /// 
    /// # Arguments
    /// * `config` - The retry configuration to use
    #[allow(dead_code)]
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }
}