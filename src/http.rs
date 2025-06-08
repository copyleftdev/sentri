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
pub struct HttpClient {
    client: Client,
    autodiscover_url: String,
    retry_config: RetryConfig,
    rate_limiter: Arc<RateLimiter>,
}

impl HttpClient {
    /// Creates a new HTTP client with optimized connection settings
    ///
    /// Initializes a client with:
    /// - HTTP/2 enabled by default
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
        let client = ClientBuilder::new()
            .timeout(timeout)
            .user_agent("AutodiscoverClient")
            .pool_max_idle_per_host(50)
            .pool_idle_timeout(Duration::from_secs(30))
            .tcp_keepalive(Duration::from_secs(60))
            .http2_prior_knowledge()
            .build()
            .context("Failed to create HTTP client")?;

        // Create a rate limiter following Microsoft's recommended limits
        let rate_limiter = Arc::new(create_microsoft_api_limiter());
        
        Ok(Self {
            client,
            autodiscover_url: "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc".to_string(),
            retry_config: RetryConfig::default(),
            rate_limiter,
        })
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
    
    /// Sets a custom rate limiter for the HTTP client
    /// 
    /// This method allows configuring a custom rate limiter for specialized
    /// rate limiting needs beyond the default settings. This is useful for
    /// testing scenarios or when specific API limit policies need to be respected.
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
    /// let custom_limiter = Arc::new(RateLimiter::new(30, 60000, 5));
    /// let client_with_limiter = client.with_rate_limiter(custom_limiter);
    /// # Ok::<(), anyhow::Error>(())
    /// # };
    /// ```
    #[allow(dead_code)]
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = limiter;
        self
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
                match err.downcast_ref::<reqwest::Error>() {
                    Some(e) if e.is_timeout() || e.is_connect() => true,
                    _ => false,
                }
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