//! Core functionality for Microsoft Defender for Identity (MDI) scanning
//!
//! This module provides the primary MDI scanning capabilities including:
//! - Domain validation and federation checking
//! - Microsoft tenant identification
//! - MDI instance verification
//! - Batch processing of domains with rate limiting
//! - Result caching for performance optimization
//!
//! All operations respect the rate limits defined in `.windsurfrules` and
//! implement proper error handling and backoff strategies.

use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
};
use tracing::{debug, error, info};

use crate::{
    dns::DnsResolver,
    http::HttpClient,
    rate_limit::RateLimiter,
    sanitize::sanitize_domain_result,
    validation::validate_domain,
    xml::XmlParser,
};

/// Results from scanning a domain for MDI presence
///
/// Contains all information collected about a domain including:
/// - The domain itself
/// - The identified Microsoft tenant (if any)
/// - All federated domains discovered
/// - The MDI instance URL (if detected)
/// - Processing metrics and any errors encountered
///
/// # Examples
///
/// ```
/// use sentri::core::DomainResult;
///
/// // Example of a successful scan result
/// let success = DomainResult {
///     domain: "example.com".to_string(),
///     tenant: Some("examplecorp".to_string()),
///     federated_domains: vec!["example.com".to_string(), "example.net".to_string()],
///     mdi_instance: Some("https://contoso-corp.atp.azure.com".to_string()),
///     processing_time_ms: 1250,
///     error: None,
/// };
///
/// // Example of a scan result with error
/// let error_result = DomainResult {
///     domain: "invalid.domain".to_string(),
///     tenant: None,
///     federated_domains: vec![],
///     mdi_instance: None,
///     processing_time_ms: 350,
///     error: Some("Invalid domain format".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainResult {
    /// The domain that was scanned
    pub domain: String,
    /// The Microsoft tenant identifier, if detected
    pub tenant: Option<String>,
    /// All domains found to be federated with the scanned domain
    pub federated_domains: Vec<String>,
    /// URL of the MDI instance if detected
    pub mdi_instance: Option<String>,
    /// Time taken to process this domain in milliseconds
    pub processing_time_ms: u64,
    /// Error message if the scan failed
    pub error: Option<String>,
}

/// Core engine for Microsoft Defender for Identity scanning
///
/// The `MdiChecker` orchestrates the entire scanning process by coordinating:
/// - HTTP requests to Microsoft autodiscover endpoints
/// - DNS resolution for domains
/// - XML parsing of federation responses
/// - Rate limiting and concurrency management
/// - Result caching for efficiency
///
/// It implements both single-domain and batch processing capabilities
/// while respecting Microsoft API rate limits and connection pooling requirements.
///
/// # Examples
///
/// ```
/// use sentri::core::MdiChecker;
/// use std::path::Path;
///
/// # async fn example() -> anyhow::Result<()> {
/// // Create a new checker with 10 concurrent requests and 5-second timeout
/// let checker = MdiChecker::new(10, 5000)?;
///
/// // Check a single domain
/// let result = checker.check_domain("example.com").await?;
/// println!("Tenant: {:?}", result.tenant);
///
/// // Process a batch of domains from a file
/// checker.process_batch(
///     Path::new("domains.txt"),
///     Some(&Path::new("results.json").to_path_buf()),
///     100,  // chunk size
///     30    // rate limit per minute
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct MdiChecker {
    /// Client for making HTTP requests to autodiscover endpoints
    http_client: Arc<HttpClient>,
    /// Resolver for DNS lookups
    dns_resolver: Arc<DnsResolver>,
    /// Parser for XML autodiscover responses
    xml_parser: Arc<XmlParser>,
    /// Maximum number of concurrent domain checks
    concurrent_limit: usize,
    /// Cache of domain check results to avoid duplicate work
    results_cache: Arc<DashMap<String, DomainResult>>,
}

impl MdiChecker {
    /// Creates a new MDI checker with specified concurrency and timeout settings
    ///
    /// This initializes all required components including HTTP client with
    /// connection pooling, DNS resolver, and XML parser for autodiscover responses.
    /// The components are wrapped in Arc for efficient sharing across async tasks.
    ///
    /// # Arguments
    /// * `concurrent_requests` - Maximum number of domain checks to run concurrently
    /// * `timeout_ms` - Timeout for HTTP requests in milliseconds
    ///
    /// # Returns
    /// * `Result<Self>` - New checker instance or error if initialization fails
    ///
    /// # Examples
    /// ```
    /// # use sentri::core::MdiChecker;
    /// # use anyhow::Result;
    /// #
    /// # fn example() -> Result<()> {
    /// // Create a checker with 5 concurrent requests and 10-second timeout
    /// let checker = MdiChecker::new(5, 10_000)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(concurrent_requests: usize, timeout_ms: u64) -> Result<Self> {
        Ok(Self {
            http_client: Arc::new(HttpClient::new(Duration::from_millis(timeout_ms))?),
            dns_resolver: Arc::new(DnsResolver::new()?),
            xml_parser: Arc::new(XmlParser::new()),
            concurrent_limit: concurrent_requests,
            results_cache: Arc::new(DashMap::new()),
        })
    }

    /// Checks a single domain for MDI presence with caching
    ///
    /// This method performs the complete MDI detection workflow:
    /// 1. Validates the domain format
    /// 2. Checks the cache for existing results
    /// 3. Retrieves federation information via SOAP request
    /// 4. Extracts tenant information
    /// 5. Checks for MDI instance presence
    /// 6. Updates the cache with results
    ///
    /// # Arguments
    /// * `domain` - Domain name to check (e.g., "example.com")
    ///
    /// # Returns
    /// * `Result<DomainResult>` - Result containing all discovered information
    ///
    /// # Examples
    /// ```
    /// # use sentri::core::MdiChecker;
    /// # use anyhow::Result;
    /// #
    /// # async fn example() -> Result<()> {
    /// let checker = MdiChecker::new(5, 10_000)?;
    /// let result = checker.check_domain("example.com").await?;
    /// 
    /// if let Some(tenant) = result.tenant {
    ///     println!("Found tenant: {}", tenant);
    /// }
    ///
    /// if let Some(error) = result.error {
    ///     eprintln!("Error checking domain: {}", error);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn check_domain(&self, domain: &str) -> Result<DomainResult> {
        let start = Instant::now();
        
        if let Some(cached) = self.results_cache.get(domain) {
            debug!("Cache hit for domain: {}", domain);
            return Ok(cached.clone());
        }

        let result = self.check_domain_impl(domain, start).await;
        
        if let Ok(ref result) = result {
            if result.error.is_none() {
                self.results_cache.insert(domain.to_string(), result.clone());
            }
        }

        result
    }

    async fn check_domain_impl(&self, domain: &str, start: Instant) -> Result<DomainResult> {
        debug!("Starting check for domain: {}", domain);
        
        if let Err(validation_error) = validate_domain(domain) {
            error!("Domain validation failed: {}", validation_error);
            return Ok(DomainResult {
                domain: domain.to_string(),
                tenant: None,
                federated_domains: vec![],
                mdi_instance: None,
                processing_time_ms: start.elapsed().as_millis() as u64,
                error: Some(validation_error),
            });
        }
        
        let federation_info = match self.get_federation_info(domain).await {
            Ok(info) => info,
            Err(e) => {
                error!("Failed to get federation info for {}: {}", domain, e);
                return Ok(DomainResult {
                    domain: domain.to_string(),
                    tenant: None,
                    federated_domains: vec![],
                    mdi_instance: None,
                    processing_time_ms: start.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                });
            }
        };

        let tenant = self.extract_tenant(&federation_info.domains);
        
        let mdi_instance = if let Some(ref tenant_name) = tenant {
            self.check_mdi_instance(tenant_name).await
        } else {
            None
        };

        Ok(DomainResult {
            domain: domain.to_string(),
            tenant: tenant.clone(),
            federated_domains: federation_info.domains,
            mdi_instance,
            processing_time_ms: start.elapsed().as_millis() as u64,
            error: None,
        })
    }

    /// Retrieves federation information for a domain from Microsoft's autodiscover service
    ///
    /// This method creates a SOAP request, sends it to Microsoft's autodiscover
    /// endpoint, and parses the response to extract federation information.
    /// It respects rate limits and implements proper error handling.
    ///
    /// # Arguments
    /// * `domain` - Domain to get federation information for
    ///
    /// # Returns
    /// * `Result<FederationInfo>` - Federation info containing all federated domains
    async fn get_federation_info(&self, domain: &str) -> Result<FederationInfo> {
        let soap_body = self.xml_parser.create_federation_request(domain);
        let response_xml = self.http_client.post_soap_request(&soap_body).await?;
        self.xml_parser.parse_federation_response(&response_xml)
    }

    /// Extracts Microsoft tenant identifier from federated domains
    ///
    /// Attempts to extract the tenant name by analyzing the patterns
    /// in the federated domains. This often appears as part of the domain
    /// name or can be derived from other characteristics.
    ///
    /// # Arguments
    /// * `domains` - List of federated domains to analyze
    ///
    /// # Returns
    /// * `Option<String>` - The tenant identifier if found, None otherwise
    fn extract_tenant(&self, domains: &[String]) -> Option<String> {
        domains
            .iter()
            .find(|d| d.ends_with(".onmicrosoft.com"))
            .and_then(|d| d.split('.').next())
            .map(String::from)
    }

    /// Checks if an MDI instance exists for the given tenant
    ///
    /// This method constructs the potential MDI instance URL based on the
    /// tenant name and performs verification to determine if it exists.
    /// Uses DNS resolution and HTTP probing with appropriate rate limiting.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier to check for MDI
    ///
    /// # Returns
    /// * `Option<String>` - The MDI instance URL if found, None otherwise
    async fn check_mdi_instance(&self, tenant: &str) -> Option<String> {
        let mdi_domain = format!("{}sensorapi.atp.azure.com", tenant);
        match self.dns_resolver.resolve(&mdi_domain).await {
            Ok(_) => {
                debug!("MDI instance found for tenant: {}", tenant);
                Some(mdi_domain)
            }
            Err(e) => {
                debug!("No MDI instance for tenant {}: {}", tenant, e);
                None
            }
        }
    }

    /// Processes a batch of domains from a file with rate limiting
    ///
    /// Reads domains from an input file, processes them in chunks with
    /// configurable rate limiting, and writes results to an output file
    /// or stdout. This method is optimized for large-scale scanning while
    /// respecting Microsoft API limits.
    ///
    /// The input file should contain one domain per line. Lines starting with '#'
    /// are treated as comments and ignored.
    ///
    /// # Arguments
    /// * `input_file` - Path to file containing domains to scan (one per line)
    /// * `output_file` - Optional path to write results as JSON (one per line)
    /// * `chunk_size` - Number of domains to process in each chunk
    /// * `rate_limit` - Maximum number of requests per minute
    ///
    /// # Returns
    /// * `Result<()>` - Success or error if processing failed
    ///
    /// # Examples
    /// ```
    /// # use sentri::core::MdiChecker;
    /// # use std::path::{Path, PathBuf};
    /// # use anyhow::Result;
    /// #
    /// # async fn example() -> Result<()> {
    /// let checker = MdiChecker::new(10, 5000)?;
    ///
    /// // Process domains with results to stdout
    /// checker.process_batch(
    ///     Path::new("domains.txt"),
    ///     None,
    ///     50,   // Process 50 domains at a time
    ///     30    // Maximum 30 requests per minute
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn process_batch(
        &self,
        input_file: &Path,
        output_file: Option<&PathBuf>,
        chunk_size: usize,
        rate_limit: u64,
    ) -> Result<()> {
        // Open output file for writing if specified
        let mut output_writer = if let Some(path) = output_file {
            Some(
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(path)
                    .await
                    .context("Failed to create output file")?,
            )
        } else {
            None
        };

        // Create rate limiter for this batch
        let rate_limiter = Arc::new(RateLimiter::new(
            rate_limit as usize,      // requests per minute
            60_000,                    // period of 60 seconds (1 minute)
            self.concurrent_limit      // max concurrent requests
        ));

        // Stream domains from file instead of loading all into memory
        // This implements the use_streaming_io rule from .windsurfrules
        let file = File::open(input_file)
            .await
            .context(format!("Failed to open domain file: {:?}", input_file))?;
        
        // Use a generous buffer size for efficiency (64KB)
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        let mut domains_processed = 0;
        let mut current_chunk = Vec::with_capacity(chunk_size);
        let mut line = String::new();
        
        info!("Processing domains from {} in streaming mode", input_file.display());
        
        // Process domains in streaming fashion without loading entire file into memory
        loop {
            line.clear(); // Reuse the string to avoid allocations
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 { // End of file
                break;
            }
            
            let domain = line.trim();
            if !domain.is_empty() && !domain.starts_with('#') {
                current_chunk.push(domain.to_string());
                
                // When we've collected enough domains, process the chunk
                if current_chunk.len() >= chunk_size {
                    domains_processed += current_chunk.len();
                    info!("Processing chunk of {} domains ({} total so far)", current_chunk.len(), domains_processed);
                    
                    let results = self.process_chunk(&current_chunk, &rate_limiter).await;
                    
                    // Stream results to output immediately as they're available
                    for result in results {
                        // Sanitize the result before outputting it (implements security:output:sanitize_all_output rule)
                        let sanitized_result = sanitize_domain_result(&result);
                        
                        if let Some(ref mut writer) = output_writer {
                            let json_line = format!("{}
", serde_json::to_string(&sanitized_result)?);
                            writer.write_all(json_line.as_bytes()).await?;
                        } else {
                            println!("{}", serde_json::to_string_pretty(&sanitized_result)?);
                        }
                    }
                    
                    // Flush after each chunk to avoid buffering too much data
                    // This follows the streaming IO principle for large datasets
                    if let Some(ref mut writer) = output_writer {
                        writer.flush().await?;
                    }
                    
                    current_chunk.clear();
                }
            }
        }
        
        // Process any remaining domains in the final chunk
        if !current_chunk.is_empty() {
            info!("Processing final chunk of {} domains", current_chunk.len());
            let results = self.process_chunk(&current_chunk, &rate_limiter).await;
            
            for result in results {
                // Sanitize the result before outputting it (implements security:output:sanitize_all_output rule)
                let sanitized_result = sanitize_domain_result(&result);
            
                if let Some(ref mut writer) = output_writer {
                    let json_line = format!("{}
", serde_json::to_string(&sanitized_result)?);
                    writer.write_all(json_line.as_bytes()).await?;
                } else {
                    println!("{}", serde_json::to_string_pretty(&sanitized_result)?);
                }
            }
            
            if let Some(ref mut writer) = output_writer {
                writer.flush().await?;
            }
        }
        
        info!("Batch processing completed, processed {} domains in total", domains_processed + current_chunk.len());
        Ok(())
    }

    /// Processes a chunk of domains concurrently with rate limiting
    ///
    /// Each domain is processed in parallel up to the concurrent_limit,
    /// with rate limiting applied to avoid overwhelming Microsoft's services.
    /// This method uses Tokio's async capabilities and Rust's concurrency
    /// features for efficient processing.
    ///
    /// # Arguments
    /// * `domains` - Slice of domains to process
    /// * `rate_limiter` - Rate limiter to control request frequency
    ///
    /// # Returns
    /// * `Vec<DomainResult>` - Results for all processed domains
    async fn process_chunk(
        &self,
        domains: &[String],
        rate_limiter: &Arc<RateLimiter>,
    ) -> Vec<DomainResult> {
        // Process domains in parallel with rate limiting
        use futures::{stream, StreamExt}; // Import in function scope to avoid conflicts
        
        stream::iter(domains)
            .map(|domain| {
                let checker = self.clone();
                let rate_limiter = rate_limiter.clone();
                let domain = domain.clone();
                
                async move {
                    // Acquire rate limit permit using our new RateLimiter
                    let permit_result = rate_limiter.acquire().await;
                    
                    // If we fail to acquire a permit, return error result
                    if let Err(e) = permit_result {
                        error!("Failed to acquire rate limit permit: {}", e);
                        return DomainResult {
                            domain: domain.clone(),
                            tenant: None,
                            federated_domains: vec![],
                            mdi_instance: None,
                            processing_time_ms: 0,
                            error: Some(format!("Rate limiting error: {}", e)),
                        };
                    }
                    
                    // Permit successfully acquired, proceed with domain check
                    let _permit = permit_result.unwrap();
                    debug!("Processing domain: {}", domain);
                    
                    let result = checker.check_domain(&domain).await;
                    
                    // Convert Result to DomainResult
                    match result {
                        Ok(domain_result) => domain_result,
                        Err(e) => DomainResult {
                            domain,
                            tenant: None,
                            federated_domains: vec![],
                            mdi_instance: None,
                            processing_time_ms: 0,
                            error: Some(e.to_string()),
                        },
                    }
                }
            })
            .buffer_unordered(self.concurrent_limit)
            .collect()
            .await
    }


    
    /// Reads domains from a text file with basic validation
    /// 
    /// This method loads all domains into memory at once. For very large files,
    /// consider using the streaming approach in `process_batch` instead.
    ///
    /// Parses a file containing one domain per line, skipping:  
    /// - Empty lines
    /// - Comment lines (starting with #)
    ///
    /// This is a legacy method retained for backward compatibility and for handling
    /// smaller domain files where loading the entire list is acceptable.
    ///
    /// # Arguments
    /// * `path` - Path to the domain list file
    ///
    /// # Returns
    /// * `Result<Vec<String>>` - List of parsed domains or error
    #[allow(dead_code)] // Retained for backward compatibility
    async fn read_domains_from_file(&self, path: &Path) -> Result<Vec<String>> {
        let file = File::open(path)
            .await
            .context(format!("Failed to open domain file: {:?}", path))?;
            
        let reader = BufReader::with_capacity(64 * 1024, file); // 64KB buffer for better performance
        let mut lines = reader.lines();
        let mut domains = Vec::new();

        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                domains.push(trimmed.to_string());
            }
        }

        Ok(domains)
    }
}

impl Clone for MdiChecker {
    fn clone(&self) -> Self {
        Self {
            http_client: Arc::clone(&self.http_client),
            dns_resolver: Arc::clone(&self.dns_resolver),
            xml_parser: Arc::clone(&self.xml_parser),
            concurrent_limit: self.concurrent_limit,
            results_cache: Arc::clone(&self.results_cache),
        }
    }
}

/// Information retrieved from federation autodiscover response
///
/// Contains all domains that are federated with the queried domain,
/// which often includes the queried domain itself plus any additional
/// domains in the same Microsoft tenant.
///
/// # Examples
///
/// ```
/// use sentri::core::FederationInfo;
///
/// let info = FederationInfo {
///     domains: vec!["example.com".to_string(), "example.org".to_string()],
/// };
///
/// assert_eq!(info.domains.len(), 2);
/// ```
#[derive(Debug)]
pub struct FederationInfo {
    /// List of all federated domains discovered
    pub domains: Vec<String>,
}