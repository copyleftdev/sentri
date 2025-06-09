use anyhow::{anyhow, Result};
use sentri::retry::{with_exponential_backoff, RetryConfig};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn test_successful_operation_returns_immediately() -> Result<()> {
    let config = RetryConfig {
        max_retries: 3,
        initial_backoff_ms: 10,
        backoff_factor: 2.0,
        max_backoff_ms: 100,
        add_jitter: false,
    };

    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let result = with_exponential_backoff(
        || async {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Ok::<_, anyhow::Error>(42)
        },
        |_| true,
        &config,
    )
    .await;

    assert_eq!(result.unwrap(), 42);
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn test_retries_until_success() -> Result<()> {
    let config = RetryConfig {
        max_retries: 3,
        initial_backoff_ms: 10,
        backoff_factor: 2.0,
        max_backoff_ms: 100,
        add_jitter: false,
    };

    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let result = with_exponential_backoff(
        || async {
            let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(anyhow!("Temporary failure"))
            } else {
                Ok(42)
            }
        },
        |_| true, // All errors are retriable
        &config,
    )
    .await;

    assert_eq!(result.unwrap(), 42);
    assert_eq!(call_count.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
async fn test_respects_max_retries() -> Result<()> {
    let config = RetryConfig {
        max_retries: 2,
        initial_backoff_ms: 10,
        backoff_factor: 2.0,
        max_backoff_ms: 100,
        add_jitter: false,
    };

    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let result: Result<i32, _> = with_exponential_backoff(
        || async {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Err(anyhow!("Persistent failure"))
        },
        |_| true, // All errors are retriable
        &config,
    )
    .await;

    assert!(result.is_err());
    assert_eq!(call_count.load(Ordering::SeqCst), 2); // Initial + 1 retry (since max_retries = 2)
    Ok(())
}

#[tokio::test]
async fn test_respects_retriable_condition() -> Result<()> {
    let config = RetryConfig {
        max_retries: 3,
        initial_backoff_ms: 10,
        backoff_factor: 2.0,
        max_backoff_ms: 100,
        add_jitter: false,
    };

    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let result: Result<i32, _> = with_exponential_backoff(
        || async {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Err(anyhow!("Non-retriable error"))
        },
        |err| !err.to_string().contains("Non-retriable"), // Only retry if error doesn't contain "Non-retriable"
        &config,
    )
    .await;

    assert!(result.is_err());
    assert_eq!(call_count.load(Ordering::SeqCst), 1); // No retries for non-retriable errors
    Ok(())
}

#[tokio::test]
async fn test_backoff_increases_exponentially() -> Result<()> {
    let config = RetryConfig {
        max_retries: 3,
        initial_backoff_ms: 10,
        backoff_factor: 2.0,
        max_backoff_ms: 1000, // High enough to not be capped
        add_jitter: false,
    };

    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let start_times = Arc::new(std::sync::Mutex::new(Vec::new()));
    let start_times_clone = start_times.clone();

    let result: Result<i32, _> = with_exponential_backoff(
        || async {
            let now = std::time::Instant::now();
            let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
            start_times_clone.lock().unwrap().push((count, now));
            Err(anyhow!("Persistent failure"))
        },
        |_| true, // All errors are retriable
        &config,
    )
    .await;

    assert!(result.is_err());
    assert_eq!(call_count.load(Ordering::SeqCst), 3); // Initial + 2 retries (since actual attempts = max_retries + 1)

    let times = start_times.lock().unwrap();
    assert_eq!(times.len(), 3);

    // Check time differences increase (approximation since exact timing is hard to test)
    if times.len() >= 3 {
        let diff1 = times[1].1.duration_since(times[0].1);
        let diff2 = times[2].1.duration_since(times[1].1);

        // The second delay should be roughly twice the first (backoff_factor = 2.0)
        // We allow some margin for system timing variations
        assert!(
            diff2 > diff1,
            "Second delay ({:?}) should be greater than first delay ({:?})",
            diff2,
            diff1
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_max_backoff_is_respected() -> Result<()> {
    let config = RetryConfig {
        max_retries: 5,
        initial_backoff_ms: 10,
        backoff_factor: 10.0, // Large factor to hit max quickly
        max_backoff_ms: 50,   // Low max to force capping
        add_jitter: false,
    };

    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let start_times = Arc::new(std::sync::Mutex::new(Vec::new()));
    let start_times_clone = start_times.clone();

    let _result: Result<i32, _> = with_exponential_backoff(
        || async {
            let now = std::time::Instant::now();
            let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
            start_times_clone.lock().unwrap().push((count, now));
            Err(anyhow!("Persistent failure"))
        },
        |_| true, // All errors are retriable
        &config,
    )
    .await;

    // After the third attempt, the backoff should be capped
    let times = start_times.lock().unwrap();
    if times.len() >= 5 {
        // Initial backoff is 10ms
        // Second should be ~100ms (10 * 10)
        // Third and all subsequent should be capped at 50ms

        let diff3 = times[3].1.duration_since(times[2].1);
        let diff4 = times[4].1.duration_since(times[3].1);

        // These should be roughly equal since both are capped
        let ratio = diff4.as_millis() as f64 / diff3.as_millis() as f64;
        assert!(
            ratio > 0.8 && ratio < 1.2,
            "Fourth delay ({:?}) should be approximately equal to third delay ({:?})",
            diff4,
            diff3
        );
    }

    Ok(())
}
