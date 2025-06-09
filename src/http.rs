//! HTTP client optimized for Microsoft Autodiscover services
//!
//! This module provides an HTTP client implementation that is specifically
//! tuned for interacting with Microsoft services with:
//! - HTTP/2 enabled for better performance
//! - Connection pooling with optimized settings
//! - TCP keepalive for connection reuse
//! - Built-in rate limiting to respect Microsoft API constraints
//! - Automatic retries with exponential backoff
//! - Error classification for better failure handling
//! - Configurable TLS certificate validation
//! - Configurable redirect limits for security
//!
//! # Security Considerations
//!
//! This module implements several key security best practices:
//!
//! - **TLS Certificate Validation**: By default, the client strictly validates all TLS certificates
//!   against trusted root CAs. This can be configured for special testing scenarios but should
//!   generally remain enabled (security:network:validate_ssl_certs).
//!
//! - **Modern TLS Versions**: The client enforces secure TLS versions (1.2+) to prevent
//!   protocol downgrade attacks (security:network:secure_tls_versions).
//!
//! - **Redirect Limits**: Redirects are limited to prevent redirect loops and potential
//!   security issues. This limit is configurable (security:network:limit_redirect_follows).
//!
//! - **Timeout Enforcement**: All network operations have mandatory timeouts to prevent
//!   resource exhaustion (security:network:timeout_all_requests).

use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder, StatusCode};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::retry::{RetryConfig, with_exponential_backoff};
use crate::rate_limit::{RateLimiter, create_microsoft_api_limiter};

/// High-performance HTTP client for Microsoft API interactions
///
/// Provides an optimized HTTP client with:
/// - HTTP/2 enabled for better connection efficiency
/// - Connection pooling to reduce connection overhead
/// - Integrated rate limiting to respect Microsoft API limits
/// - Automatic retries with exponential backoff for resilience
/// - Custom timeout and user-agent management
/// - Configurable TLS certificate validation
/// - Configurable redirect following limits
///
/// # Security Features
///
/// The client enforces several security best practices by default:
///
/// - **Certificate Validation**: All TLS certificates are strictly validated against trusted
///   root certificate authorities (security:network:validate_ssl_certs)
/// - **TLS Version Security**: Only secure TLS versions (1.2+) are allowed to prevent downgrade
///   attacks (security:network:secure_tls_versions)
/// - **Redirect Limits**: Redirects are limited to 5 by default to prevent redirect loops and
///   security issues (security:network:limit_redirect_follows)
/// - **Request Timeouts**: All requests have a mandatory timeout to prevent resource exhaustion
///   (security:network:timeout_all_requests)
///
/// # Examples
///
/// ```
/// use sentri::http::HttpClient;
/// use std::time::Duration;
///
/// # async fn example() -> anyhow::Result<()> {
/// // Create a client with a 10-second timeout
/// let client = HttpClient::new(Duration::from_secs(10))?;
/// 
/// // Send a SOAP request
/// let response = client.post_soap_request("<soap:Envelope>...</soap:Envelope>").await?;
/// # Ok(())
/// # }
/// ```
///
/// Advanced configuration with security settings:
///
/// ```
/// use sentri::http::HttpClient;
/// use std::time::Duration;
///
/// # async fn example() -> anyhow::Result<()> {
/// // Create a client with custom security settings
/// let client = HttpClient::builder()
///     .timeout(Duration::from_secs(10))
///     .max_redirects(3)  // Stricter redirect policy
///     .build()?;
///     
/// # Ok(())
/// # }
/// ```
pub struct HttpClient {
    client: Client,
    autodiscover_url: String,
    retry_config: RetryConfig,
    rate_limiter: Arc<RateLimiter>,
}

/// Builder for configuring and constructing an HttpClient
///
/// This builder provides fine-grained control over the HTTP client configuration,
/// especially for security-related settings like certificate validation and redirect limits.
/// It follows the builder pattern for a fluent API.
///
/// # Security Considerations
/// 
/// - Certificate validation is enabled by default and should remain enabled in production
///   environments (security:network:validate_ssl_certs).
/// - Redirect limits default to 5 to prevent redirect loops and potential security issues
///   (security:network:limit_redirect_follows).
/// - Minimum TLS version is set to 1.2 to prevent protocol downgrade attacks
///   (security:network:secure_tls_versions).
/// - All requests have mandatory timeout settings to prevent resource exhaustion
///   (security:network:timeout_all_requests).
///
/// # Examples
/// 
/// ```
/// use sentri::http::HttpClient;
/// use std::time::Duration;
/// 
/// # fn example() -> anyhow::Result<()> {
/// // Create a client with custom settings
/// let client = HttpClient::builder()
///     .timeout(Duration::from_secs(15))
///     .max_redirects(3)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct HttpClientBuilder {
    timeout: Duration,
    max_redirects: u32,
    verify_certificates: bool,
    min_tls_version: Option<reqwest::tls::Version>,
    user_agent: String,
    idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
    tcp_keepalive: Duration,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self {
            // Default 30 second timeout for all requests
            timeout: Duration::from_secs(30),
            // Default limit of 5 redirects (security:network:limit_redirect_follows)
            max_redirects: 5,
            // Certificate validation enabled by default (security:network:validate_ssl_certs)
            verify_certificates: true,
            // Minimum TLS 1.2 (security:network:secure_tls_versions)
            min_tls_version: Some(reqwest::tls::Version::TLS_1_2),
            // Standard user agent
            user_agent: format!("sentri-mdi-scanner/{}", env!("CARGO_PKG_VERSION")),
            // Default idle timeout of 90 seconds
            idle_timeout: Some(Duration::from_secs(90)),
            // Connection pool settings
            pool_max_idle_per_host: 50,
            pool_idle_timeout: Duration::from_secs(30),
            tcp_keepalive: Duration::from_secs(60),
        }
    }
}

impl HttpClientBuilder {
    /// Sets the request timeout
    ///
    /// The timeout includes the full request-response cycle including DNS resolution,
    /// connection establishment, request transmission, and response reception.
    ///
    /// # Arguments
    /// * `timeout` - The timeout duration for requests
    ///
    /// # Returns
    /// * `Self` - The builder with the timeout configured
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum number of redirects to follow
    ///
    /// This is a security feature to prevent redirect loops and potential security
    /// issues like open redirectors. The default is 5 redirects.
    /// (security:network:limit_redirect_follows)
    ///
    /// # Arguments
    /// * `max_redirects` - Maximum number of redirects to follow (0 to disable redirects)
    ///
    /// # Returns
    /// * `Self` - The builder with redirect limit configured
    pub fn max_redirects(mut self, max_redirects: u32) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Controls whether to verify TLS certificates
    ///
    /// WARNING: Disabling certificate validation is strongly discouraged and should
    /// only be used in exceptional circumstances such as testing environments with
    /// self-signed certificates. Never disable in production.
    /// (security:network:validate_ssl_certs)
    ///
    /// # Arguments
    /// * `verify` - Whether to verify certificates (default: true)
    ///
    /// # Returns
    /// * `Self` - The builder with certificate validation configured
    pub fn verify_certificates(mut self, verify: bool) -> Self {
        self.verify_certificates = verify;
        self
    }

    /// Sets the minimum TLS version to use
    ///
    /// This is a security feature to prevent protocol downgrade attacks.
    /// The default is TLS 1.2. (security:network:secure_tls_versions)
    ///
    /// # Arguments
    /// * `version` - Minimum TLS version to use
    ///
    /// # Returns
    /// * `Self` - The builder with TLS version configured
    pub fn min_tls_version(mut self, version: reqwest::tls::Version) -> Self {
        self.min_tls_version = Some(version);
        self
    }

    /// Sets the user agent string for requests
    ///
    /// # Arguments
    /// * `user_agent` - User agent string
    ///
    /// # Returns
    /// * `Self` - The builder with user agent configured
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Sets the timeout for idle connections in the connection pool.
    ///
    /// This configures how long a connection remains idle in the pool before being closed.
    /// Setting an appropriate idle timeout helps optimize resource usage by closing connections
    /// that are unlikely to be reused, while maintaining ones that are frequently accessed.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The duration after which an idle connection will be closed
    ///               Set to None to keep connections alive indefinitely (not recommended)
    ///
    /// # Security Considerations
    ///
    /// Setting an appropriate idle timeout helps prevent resource exhaustion and is a
    /// recommended security practice according to the project's security policies.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sentri::http::HttpClient;
    /// # use std::time::Duration;
    /// #
    /// let client = HttpClient::builder()
    ///     .idle_timeout(Duration::from_secs(60))
    ///     .build()
    ///     .expect("Failed to create HTTP client");
    /// ```
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Disables idle timeout for connections in the pool.
    ///
    /// This will keep connections alive as long as possible, which may be useful
    /// in high-throughput scenarios where connections are constantly reused.
    ///
    /// # Warning
    ///
    /// Disabling idle timeout may lead to excessive resource consumption if many
    /// connections are opened and rarely reused. Use with caution.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sentri::http::HttpClient;
    /// #
    /// let client = HttpClient::builder()
    ///     .disable_idle_timeout()
    ///     .build()
    ///     .expect("Failed to create HTTP client");
    /// ```
    pub fn disable_idle_timeout(mut self) -> Self {
        self.idle_timeout = None;
        self
    }

    /// Builds the HttpClient with the configured settings
    ///
    /// # Returns
    /// * `Result<HttpClient>` - The configured client or error if build failed
    ///
    /// # Errors
    /// * Returns error if client creation fails
    pub fn build(self) -> Result<HttpClient> {
        let mut builder = ClientBuilder::new()
            .timeout(self.timeout)
            .user_agent(&self.user_agent)
            .pool_max_idle_per_host(self.pool_max_idle_per_host)
            .pool_idle_timeout(self.pool_idle_timeout)
            .tcp_keepalive(self.tcp_keepalive)
            .danger_accept_invalid_certs(!self.verify_certificates)
            .https_only(true)  // Force HTTPS for security
            .http2_prior_knowledge();

        // Configure redirect policy
        if self.max_redirects > 0 {
            builder = builder.redirect(reqwest::redirect::Policy::limited(self.max_redirects as usize));
        } else {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        // Set minimum TLS version if specified
        if let Some(version) = self.min_tls_version {
            builder = builder.min_tls_version(version);
        }

        // Apply idle timeout if configured
        if let Some(idle_timeout) = self.idle_timeout {
            builder = builder.pool_idle_timeout(idle_timeout);
        } else {
            builder = builder.pool_idle_timeout(None);
        }

        let client = builder.build().context("Failed to create HTTP client")?;

        // Create a rate limiter following Microsoft's recommended limits
        let rate_limiter = Arc::new(create_microsoft_api_limiter());
        
        Ok(HttpClient {
            client,
            autodiscover_url: "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc".to_string(),
            retry_config: RetryConfig::default(),
            rate_limiter,
        })
    }
}

impl HttpClient {
    /// Creates a new HTTP client with optimized connection settings
    ///
    /// Initializes a client with:
    /// - HTTP/2 enabled by default
    /// - TLS certificate validation enabled
    /// - Maximum 5 redirects allowed
    /// - Minimum TLS version 1.2
    /// - 50 max idle connections per host
    /// - 30 second connection idle timeout
    /// - 60 second TCP keepalive
    /// - Standard retry configuration
    /// - Microsoft-recommended rate limits
    ///
    /// # Arguments
    /// * `timeout` - Request timeout duration
    ///
    /// # Returns
    /// * `Result<Self>` - A configured client or error if initialization failed
    ///
    /// # Examples
    ///
    /// ```
    /// use sentri::http::HttpClient;
    /// use std::time::Duration;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// // Create a client with a 10-second timeout
    /// let client = HttpClient::new(Duration::from_secs(10))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(timeout: Duration) -> Result<Self> {
        Self::builder().timeout(timeout).build()
    }
    
    /// Returns a new builder for creating an HttpClient with custom configuration
    ///
    /// # Returns
    /// * `HttpClientBuilder` - A builder for configuring the client
    ///
    /// # Examples
    ///
    /// ```
    /// use sentri::http::HttpClient;
    /// use std::time::Duration;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let client = HttpClient::builder()
    ///     .timeout(Duration::from_secs(30))
    ///     .max_redirects(3)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::default()
    }
    
    /// Sets a custom rate limiter for the HTTP client
    /// 
    /// This method allows configuring a custom rate limiter for specialized
    /// rate limiting needs beyond the default settings. This is useful for
    /// testing scenarios or when specific rate limiting policies need to be respected.
    /// 
    /// # Arguments
    /// * `limiter` - The custom rate limiter to use
    /// 
    /// # Returns
    /// * `Self` - The HTTP client with custom rate limiter configured
    /// 
    /// # Examples
    /// ```
    /// # use sentri::http::HttpClient;
    /// # use sentri::rate_limit::RateLimiter;
    /// # use std::sync::Arc;
    /// # use std::time::Duration;
    /// # async {
    /// let client = HttpClient::new(Duration::from_secs(10))?;
    /// let custom_limiter = Arc::new(RateLimiter::new(50, 60000, 10));
    /// let client_with_limiter = client.with_rate_limiter(custom_limiter);
    /// # Ok::<(), anyhow::Error>(())
    /// # };
    /// ```
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = limiter;
        self
    }

    /// Sets a custom retry configuration for the HTTP client
    /// 
    /// # Arguments
    /// * `config` - The retry configuration to use
    #[allow(dead_code)]
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }
    
    /// Determines if a response error is retriable
    /// 
    /// # Arguments
    /// * `status` - The HTTP status code to check
    /// * `retry_count` - The current retry count
    /// 
    /// # Returns
    /// True if the error is retriable, false otherwise
    fn is_retriable_status(&self, status: StatusCode) -> bool {
        // 429 is too many requests (rate limiting)
        // 5xx are server errors that may be transient
        status.as_u16() == 429 || status.is_server_error()
    }
    
    /// Sends a SOAP request to the autodiscover endpoint with exponential backoff retries
    /// 
    /// This method handles the complete request workflow:
    /// 1. Applies rate limiting before making the request
    /// 2. Sets appropriate SOAP headers
    /// 3. Automatically retries on transient failures
    /// 4. Provides detailed error context for troubleshooting
    /// 
    /// # Arguments
    /// * `body` - The SOAP XML body to send
    /// 
    /// # Returns
    /// * `Result<String>` - The response text or error
    /// 
    /// # Examples
    /// 
    /// ```
    /// # use sentri::http::HttpClient;
    /// # use std::time::Duration;
    /// # async fn example() -> anyhow::Result<()> {
    /// let client = HttpClient::new(Duration::from_secs(10))?;
    /// 
    /// // Example SOAP envelope (simplified)
    /// let soap_body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    ///   <soap:Body>
    ///     <GetFederationInformation xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
    ///       <domain>example.com</domain>
    ///     </GetFederationInformation>
    ///   </soap:Body>
    /// </soap:Envelope>"#;
    /// 
    /// let response = client.post_soap_request(soap_body).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn post_soap_request(&self, body: &str) -> Result<String> {
        debug!("Sending SOAP request to autodiscover endpoint");
        
        // Acquire rate limit permit before proceeding
        debug!("Acquiring rate limit permit");
        let _permit = self.rate_limiter.acquire().await?;
        debug!("Rate limit permit acquired, proceeding with request");
        
        let body_owned = body.to_string();
        let client = self.client.clone();
        let url = self.autodiscover_url.clone();
        let retry_config = &self.retry_config;

        // Use exponential backoff for the request
        let response = with_exponential_backoff(
            || async {
                let resp = client
                    .post(&url)
                    .header("Content-Type", "text/xml; charset=utf-8")
                    .header("SOAPAction", "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation")
                    .body(body_owned.clone())
                    .send()
                    .await
                    .context("Failed to send SOAP request")?;
                
                // Check if the response status indicates success
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err = anyhow::anyhow!("HTTP request failed with status: {}", status);
                    
                    // Log different messages based on status code
                    if status.as_u16() == 429 {
                        warn!("Rate limit exceeded, will retry: {}", status);
                    } else if status.is_server_error() {
                        warn!("Server error, will retry: {}", status);
                    } else {
                        // Client errors (4xx) other than 429 are not generally retriable
                        info!("Non-retriable client error: {}", status);
                    }
                    
                    return Err(err);
                }
                
                Ok(resp)
            },
            |err| {
                // Check if this is an error with a status code we can retry on
                if let Some(status) = err.chain()
                    .filter_map(|e| e.downcast_ref::<reqwest::Error>())
                    .filter_map(|e| e.status())
                    .next() 
                {
                    return self.is_retriable_status(status);
                }
                
                // Network errors, timeouts, etc. are all retriable
                matches!(err.downcast_ref::<reqwest::Error>(), Some(e) if e.is_timeout() || e.is_connect())
            },
            retry_config,
        )
        .await?;

        let response_text = response
            .text()
            .await
            .context("Failed to read response body")?;

        debug!("Received SOAP response");
        Ok(response_text)
    }
}
