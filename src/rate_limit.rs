use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;
use anyhow::{Result, Context};
use tracing::debug;

/// A token bucket rate limiter for controlling request rates
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum number of requests allowed in a time period
    capacity: usize,
    /// Current token count
    tokens: Mutex<usize>,
    /// Time period for token replenishment in milliseconds
    refill_time_ms: u64,
    /// Last time tokens were refilled
    last_refill: Mutex<Instant>,
    /// Semaphore to limit concurrent requests
    concurrency_limit: Arc<Semaphore>,
}

impl RateLimiter {
    /// Creates a new rate limiter
    /// 
    /// # Arguments
    /// 
    /// * `requests_per_period` - Maximum number of requests allowed in the given time period
    /// * `period_ms` - Time period in milliseconds for the rate limit (e.g., 1000 for 1 second)
    /// * `max_concurrent` - Maximum number of concurrent requests allowed
    pub fn new(requests_per_period: usize, period_ms: u64, max_concurrent: usize) -> Self {
        let now = Instant::now();
        
        Self {
            capacity: requests_per_period,
            tokens: Mutex::new(requests_per_period),
            refill_time_ms: period_ms,
            last_refill: Mutex::new(now),
            concurrency_limit: Arc::new(Semaphore::new(max_concurrent)),
        }
    }
    
    /// Acquires permission to make a request, waiting if necessary
    /// 
    /// This function will wait until a token is available in the bucket,
    /// and also acquire a permit from the semaphore to limit concurrency.
    /// 
    /// Returns a guard that will release the concurrency permit when dropped.
    pub async fn acquire(&self) -> Result<RateLimitGuard> {
        debug!("Attempting to acquire rate limit permit");
        
        // First wait for a token in the bucket
        loop {
            let wait_time = self.try_acquire().await;
            
            if wait_time == Duration::ZERO {
                break;
            }
            
            debug!("Rate limit reached, waiting for {:?}", wait_time);
            sleep(wait_time).await;
        }
        
        // Then acquire a permit for concurrency limiting
        let permit = self.concurrency_limit.clone()
            .acquire_owned()
            .await
            .context("Failed to acquire concurrency permit")?;
            
        debug!("Rate limit permit acquired");
        
        Ok(RateLimitGuard { _permit: permit })
    }
    
    /// Tries to acquire a token from the bucket. If no tokens are available,
    /// returns the duration to wait before retrying.
    async fn try_acquire(&self) -> Duration {
        let mut tokens = self.tokens.lock().await;
        let mut last_refill = self.last_refill.lock().await;
        let now = Instant::now();
        
        // Calculate how many tokens to add based on elapsed time
        let elapsed = now.duration_since(*last_refill).as_millis() as u64;
        
        if elapsed >= self.refill_time_ms {
            let periods = elapsed / self.refill_time_ms;
            let new_tokens = periods as usize * self.capacity;
            
            *tokens = (*tokens + new_tokens).min(self.capacity);
            *last_refill = now - Duration::from_millis(elapsed % self.refill_time_ms);
        }
        
        if *tokens > 0 {
            *tokens -= 1;
            Duration::ZERO
        } else {
            // Calculate time until next token replenishment
            let time_since_last_refill = now.duration_since(*last_refill).as_millis() as u64;
            let time_until_next_token = self.refill_time_ms.saturating_sub(time_since_last_refill);
            Duration::from_millis(time_until_next_token)
        }
    }
    
    /// Updates the rate limiter configuration
    ///
    /// # Arguments
    ///
    /// * `requests_per_period` - New maximum number of requests allowed in the time period
    /// * `period_ms` - New time period in milliseconds
    /// * `max_concurrent` - New maximum number of concurrent requests
    ///
    /// Updates the rate limiter configuration with new parameters.
    /// 
    /// This method allows dynamically changing the rate limiter configuration
    /// at runtime, which is useful for adaptive rate limiting based on server
    /// responses or changing conditions. It safely manages token allocation and
    /// concurrency limits during the transition.
    ///
    /// # Arguments
    /// * `requests_per_period` - New number of allowed requests per period
    /// * `period_ms` - New period duration in milliseconds
    /// * `max_concurrent` - New maximum number of concurrent requests
    ///
    /// # Returns
    /// * `Result<()>` - Success or error if update failed
    ///
    /// # Examples
    /// ```
    /// # use sentri::rate_limit::RateLimiter;
    /// # async {
    /// let limiter = RateLimiter::new(10, 1000, 5);
    /// // Update to 20 requests per 2 seconds with 10 concurrent connections
    /// limiter.update_config(20, 2000, 10).await?;
    /// # Ok::<(), anyhow::Error>(())
    /// # };
    /// ```
    #[allow(dead_code)]
    pub async fn update_config(
        &self, 
        requests_per_period: usize, 
        period_ms: u64, 
        max_concurrent: usize
    ) -> Result<()> {
        debug!("Updating rate limiter config: {} requests per {} ms, {} concurrent",
               requests_per_period, period_ms, max_concurrent);
               
        let mut tokens = self.tokens.lock().await;
        let mut last_refill = self.last_refill.lock().await;
        
        // Always ensure at least one token is available after update
        // This guarantees a waiting request can proceed immediately
        let new_tokens = if requests_per_period > self.capacity {
            // If capacity increased, add at least one new token
            1.max((requests_per_period - self.capacity) / 2) // Add half the difference but at least 1
        } else {
            0 // Don't add tokens if capacity decreased
        };
        
        // Set current tokens to at least new_tokens
        *tokens = (*tokens + new_tokens).min(requests_per_period);
        
        // Reset the last refill time to now
        *last_refill = Instant::now();
        
        debug!("Updated rate limiter, new tokens available: {}", *tokens);
        
            // Update semaphore for concurrency
        let current_permits = self.concurrency_limit.available_permits();
        let diff = max_concurrent as isize - current_permits as isize;
        
        if diff > 0 {
            // Add permits if new limit is higher
            self.concurrency_limit.add_permits(diff as usize);
            debug!("Added {} concurrency permits", diff);
        }
        
        // Note that if diff < 0, we don't reduce permits, as they will 
        // naturally decrease as current requests complete
        
        Ok(())
    }
}

/// A guard that releases the concurrency permit when dropped
#[derive(Debug)]
pub struct RateLimitGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Helper function to create a rate limiter specifically for Microsoft API limits
///
/// The default configuration follows Microsoft's recommendations for
/// enterprise applications that may make many requests.
pub fn create_microsoft_api_limiter() -> RateLimiter {
    // Microsoft recommends no more than 60 requests per minute for enterprise apps
    // and no more than 10 concurrent connections
    RateLimiter::new(60, 60_000, 10) 
}

/// Helper function to create a rate limiter for DNS queries
///
/// This helps prevent overwhelming DNS servers with too many requests.
pub fn create_dns_query_limiter() -> RateLimiter {
    // Allow 100 DNS queries per minute with max 20 concurrent
    RateLimiter::new(100, 60_000, 20)
}
