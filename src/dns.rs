use anyhow::{Context, Result};
use std::net::IpAddr;
use std::sync::Arc;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::TokioAsyncResolver as AsyncResolver;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use tracing::{debug, warn};
use crate::retry::{RetryConfig, with_exponential_backoff};
use crate::rate_limit::{RateLimiter, create_dns_query_limiter};

pub struct DnsResolver {
    resolver: AsyncResolver,
    retry_config: RetryConfig,
    rate_limiter: Arc<RateLimiter>,
}

impl DnsResolver {
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