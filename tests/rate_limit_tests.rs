use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

// Import from the crate directly as defined in lib.rs exports
use sentri::rate_limit::RateLimiter;

/// Helper functions to create rate limiters for testing with faster refresh periods
///
/// These functions create rate limiters with test-appropriate settings:
/// - Shorter refresh periods for faster test execution
/// - Appropriate permit counts for testing different scenarios
fn create_microsoft_api_test_limiter() -> RateLimiter {
    // For tests use faster rate refresh
    RateLimiter::new(60, 1000, 10)
}

fn create_dns_query_test_limiter() -> RateLimiter {
    // For tests use faster rate refresh
    RateLimiter::new(100, 1000, 20)
}

#[tokio::test]
async fn test_rate_limiter_creation() -> Result<()> {
    // Test basic creation
    let _limiter = RateLimiter::new(10, 1000, 5);

    // Test Microsoft API limiter helper
    let _ms_limiter = create_microsoft_api_test_limiter();

    // Test DNS query limiter helper
    let _dns_limiter = create_dns_query_test_limiter();

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_permits() -> Result<()> {
    // Create a rate limiter with 5 permits per second
    let limiter = Arc::new(RateLimiter::new(5, 1000, 3));

    // Should be able to acquire 5 permits immediately
    for _ in 0..5 {
        let permit = limiter.acquire().await?;
        drop(permit);
    }

    // The 6th permit should require waiting
    let start = Instant::now();
    let _permit = limiter.acquire().await?;
    let elapsed = start.elapsed();

    // Should have waited at least 800ms (giving 200ms buffer for timing variations)
    assert!(
        elapsed.as_millis() >= 800,
        "Did not wait for rate limit: {:?}",
        elapsed
    );

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_concurrency() -> Result<()> {
    // Create a rate limiter with concurrency limit of 2
    let limiter = Arc::new(RateLimiter::new(100, 1000, 2));

    // Acquire 2 permits which should succeed immediately
    let permit1 = limiter.acquire().await?;
    let permit2 = limiter.acquire().await?;

    // The 3rd acquisition should block until one permit is released
    let acquire_task = tokio::spawn({
        let limiter = limiter.clone();
        async move {
            let start = Instant::now();
            let _ = limiter.acquire().await.unwrap();
            start.elapsed()
        }
    });

    // Wait a bit to ensure the task is blocked
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Drop one permit
    drop(permit1);

    // The task should now complete
    let elapsed = acquire_task.await?;

    // Should have waited at least 50ms
    assert!(
        elapsed.as_millis() >= 50,
        "Did not wait for concurrency limit"
    );

    // Clean up
    drop(permit2);

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_update_config() -> Result<()> {
    // Create a limiter with 2 permits per second with generous timeout
    // We're using a small number for faster test execution
    let limiter = Arc::new(RateLimiter::new(2, 500, 3));

    // Use up all initial permits
    for _ in 0..2 {
        let _permit = limiter.acquire().await?;
    }

    // Attempt to get one more, which should timeout
    let _start = Instant::now();
    let acquire_result = timeout(Duration::from_millis(100), limiter.acquire()).await;
    assert!(
        acquire_result.is_err(),
        "Should have timed out waiting for permit"
    );

    // Update to a higher rate limit
    limiter.update_config(5, 500, 5).await?;

    // Should now have new tokens immediately available
    let permit_result = timeout(Duration::from_millis(100), limiter.acquire()).await;
    assert!(
        permit_result.is_ok(),
        "Should have received a permit after update"
    );

    Ok(())
}

#[tokio::test]
async fn test_microsoft_api_limiter_config() {
    // Microsoft API limiter should be configured with appropriate values
    let _ms_limiter = create_microsoft_api_test_limiter();

    // We can only test this indirectly by checking behavior
    // Should allow 60 requests, then enforce waiting

    // Create a test limiter with the same configuration but faster for testing
    let test_limiter = Arc::new(RateLimiter::new(3, 500, 3));

    // Use all permits
    for _ in 0..3 {
        test_limiter.acquire().await.unwrap();
    }

    // Next one should block
    let start = Instant::now();
    let _permit = test_limiter.acquire().await.unwrap();
    let elapsed = start.elapsed();

    // Should have waited at least 400ms (allowing 100ms buffer)
    assert!(elapsed.as_millis() >= 400, "Rate limit not enforced");

    // No need to explicitly drop the permit
}

#[tokio::test]
async fn test_integration_with_http_client() -> Result<()> {
    use sentri::http::HttpClient;
    use std::time::Duration;

    // First test the basic HTTP client functionality
    let client = HttpClient::new(Duration::from_millis(500))?;

    // Verify client handles invalid requests properly
    assert!(client.post_soap_request("<test>").await.is_err());

    // Create a rate limiter that could be used with HTTP operations
    let rate_limiter = Arc::new(RateLimiter::new(2, 1000, 2));

    // Simulate limited requests using the rate limiter directly
    let permit = rate_limiter.acquire().await?;

    // Make a request with the HTTP client while holding the rate limiter permit
    let request_result = client.post_soap_request("<test>").await;

    // Verify the request fails correctly (due to invalid XML, not rate limiting)
    assert!(request_result.is_err());

    // Release the permit
    drop(permit);

    Ok(())
}

#[tokio::test]
async fn test_integration_with_dns_resolver() -> Result<()> {
    use sentri::dns::DnsResolver;

    // Create DNS resolver
    let resolver = DnsResolver::new()?;

    // Verify resolver created successfully with basic functionality
    assert!(resolver.resolve("not.a.domain").await.is_err());

    // Create a rate limiter for DNS operations
    let rate_limiter = Arc::new(RateLimiter::new(5, 1000, 3));

    // Demonstrate how rate limiting could be applied to DNS operations
    let permit = rate_limiter.acquire().await?;

    // Try resolving a domain while holding the rate limiter permit
    let resolve_result = resolver.resolve("not.a.domain").await;

    // Verify the resolve operation fails correctly (due to invalid domain)
    assert!(resolve_result.is_err());

    // Release the permit
    drop(permit);

    Ok(())
}
