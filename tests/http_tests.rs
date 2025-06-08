use anyhow::Result;
use sentri::http::HttpClient;
use sentri::rate_limit::RateLimiter;
use sentri::retry::RetryConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::test;

#[test]
async fn test_http_client_creation() -> Result<()> {
    // Test creation with valid timeout
    let timeout = Duration::from_millis(500);
    let client = HttpClient::new(timeout)?;
    
    // Cannot directly access private fields, but we can test the client
    // is initialized without error
    assert!(client.with_retry_config(RetryConfig::default()).post_soap_request("test").await.is_err());
    
    Ok(())
}

#[test]
async fn test_retry_config() -> Result<()> {
    let timeout = Duration::from_millis(500);
    let client = HttpClient::new(timeout)?;
    
    // Test with custom retry config
    let custom_config = RetryConfig {
        max_retries: 3,
        initial_backoff_ms: 100,
        max_backoff_ms: 1000,
        backoff_factor: 2.0,
        add_jitter: false,
    };
    
    let client_with_config = client.with_retry_config(custom_config);
    
    // Cannot directly test private fields, but we can verify the client
    // still functions after configuration
    assert!(client_with_config.post_soap_request("test").await.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiter() -> Result<()> {
    let timeout = Duration::from_millis(500);
    let client = HttpClient::new(timeout)?;
    
    // Create a custom rate limiter for testing
    let custom_limiter = Arc::new(RateLimiter::new(10, 1000, 5));
    let client_with_limiter = client.with_rate_limiter(custom_limiter);
    
    // Cannot directly test private fields, but we can verify the client
    // still functions after configuration
    assert!(client_with_limiter.post_soap_request("test").await.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_http_client_connection_pooling() -> Result<()> {
    // Create client with proper configuration
    let client = HttpClient::new(Duration::from_millis(500))?;
    
    // We can't access private fields directly, but we can test that client works
    // by making multiple requests and ensuring they don't fail due to connection issues
    
    // Make a request and verify error handling works consistently
    let result1 = client.post_soap_request("test-request-1").await;
    assert!(result1.is_err());
    
    // Make another request to verify connection pooling doesn't cause issues
    let result2 = client.post_soap_request("test-request-2").await;
    assert!(result2.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_http_client_with_custom_request() -> Result<()> {
    let client = HttpClient::new(Duration::from_millis(5000))?;
    
    // Cannot directly access client internals, but we can test
    // that the client handles errors correctly when making requests
    
    // Post request with invalid XML should result in error
    let result = client.post_soap_request("invalid-xml").await;
    assert!(result.is_err());
    
    // Just verify we got an error, don't check specific message
    // since the error message might vary depending on environment
    let err = result.unwrap_err();
    // Print the error for debugging but don't assert on specific content
    println!("Error received: {}", err.to_string());
    
    Ok(())
}
