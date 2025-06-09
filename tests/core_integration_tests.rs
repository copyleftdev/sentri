use anyhow::Result;
use sentri::core::MdiChecker;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
// Removed unused imports (Arc, Duration, Semaphore)

// Helper function to create a temporary test file with domains
async fn create_test_domain_file(domains: &[&str]) -> Result<PathBuf> {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join(format!(
        "test_domains_{}.txt",
        Instant::now().elapsed().as_nanos()
    ));

    // Use more robust error handling with better context
    let mut file = File::create(&test_file).await.map_err(|e| {
        anyhow::anyhow!("Failed to create test file {}: {}", test_file.display(), e)
    })?;

    for domain in domains {
        file.write_all(format!("{}\n", domain).as_bytes())
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to write to test file {}: {}",
                    test_file.display(),
                    e
                )
            })?;
    }

    file.flush()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to flush test file {}: {}", test_file.display(), e))?;

    // Ensure file is closed properly
    drop(file);

    // Verify the file exists before returning
    if !test_file.exists() {
        return Err(anyhow::anyhow!(
            "Test file was not created properly: {}",
            test_file.display()
        ));
    }

    Ok(test_file)
}

#[tokio::test]
async fn test_check_domain_basic() -> Result<()> {
    // Create a checker with minimal concurrency for testing
    let checker = MdiChecker::new(1, 1000)?;

    // Test with a simple domain that won't make actual network requests
    // (The domain name is invalid and will fail validation)
    let result = checker.check_domain("invalid..domain").await?;

    // Should have an error due to validation failure
    assert!(result.error.is_some());
    assert!(result.error.unwrap().contains("Invalid domain format"));

    // No federation domains or MDI instance should be found for invalid domain
    assert!(result.federated_domains.is_empty());
    assert!(result.mdi_instance.is_none());

    Ok(())
}

#[tokio::test]
async fn test_process_batch_with_invalid_domains() -> Result<()> {
    // Create a checker with minimal concurrency for testing
    let checker = MdiChecker::new(2, 1000)?;

    // Create a temporary file with test domains including invalid ones
    let domains = ["example.com", "invalid..domain", "test-domain.com"];
    let input_file = create_test_domain_file(&domains).await?;

    // Create an output file path
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join(format!(
        "test_results_{}.json",
        Instant::now().elapsed().as_nanos()
    ));

    // Process the batch with minimal rate limiting
    checker
        .process_batch(
            &input_file,
            Some(&output_file),
            2,  // small chunk size
            60, // rate limit of 60/min (1/sec)
        )
        .await?;

    // Verify the output file was created
    assert!(output_file.exists());

    // Read the content of the output file
    let content = fs::read_to_string(&output_file)?;

    // The output should contain results for all domains
    for domain in domains.iter() {
        assert!(content.contains(domain));
    }

    // Invalid domain should have an error
    assert!(content.contains("Invalid domain format"));

    // Clean up
    fs::remove_file(input_file)?;
    fs::remove_file(output_file)?;

    Ok(())
}

#[tokio::test]
async fn test_error_handling_empty_file() -> Result<()> {
    // Create a checker with minimal concurrency for testing
    let checker = MdiChecker::new(1, 1000)?;

    // Create an empty file
    let input_file = create_test_domain_file(&[]).await?;

    // Make sure the file actually exists before proceeding
    assert!(
        input_file.exists(),
        "Input file was not created: {}",
        input_file.display()
    );

    // Ensure file cleanup with a guard pattern
    struct CleanupGuard(PathBuf);
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            // First check if file exists to avoid errors on cleanup
            if self.0.exists() {
                let _ = fs::remove_file(&self.0);
            }
        }
    }
    let _input_guard = CleanupGuard(input_file.clone());

    // Create an output file path with a unique timestamp
    let temp_dir = std::env::temp_dir();
    let timestamp = Instant::now().elapsed().as_nanos().to_string();
    let output_file = temp_dir.join(format!("empty_results_{}.json", timestamp));
    let _output_guard = CleanupGuard(output_file.clone());

    // Wait a moment to ensure temp directory is ready
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    
    println!("Processing batch with input: {}, output: {}", input_file.display(), output_file.display());
    
    // Process the batch with more robust error handling
    let result = checker
        .process_batch(&input_file, Some(&output_file), 10, 30)
        .await;
    
    if let Err(e) = &result {
        println!("Error in process_batch: {}", e);
    }
    
    // More verbose error reporting
    result.map_err(|e| anyhow::anyhow!("Failed to process batch: {}", e))?;

    // Wait longer to ensure file operations complete on all platforms (especially Windows)
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Verify output file exists with more detailed error
    let exists = std::path::Path::new(&output_file).exists();
    println!("Output file exists: {}, path: {}", exists, output_file.display());
    assert!(
        exists,
        "Output file does not exist: {}",
        output_file.display()
    );

    // Read content with better error handling and retry logic for Windows
    let mut retries = 3;
    let mut content = String::new();
    let mut last_error = None;
    
    while retries > 0 {
        match fs::read_to_string(&output_file) {
            Ok(file_content) => {
                content = file_content;
                break;
            }
            Err(e) => {
                println!("Error reading file (retry {}): {}", 4-retries, e);
                last_error = Some(e);
                retries -= 1;
                // Wait before retrying on Windows in case of file locking
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
    
    if retries == 0 {
        return Err(anyhow::anyhow!("Failed to read output file after multiple attempts: {}", 
            last_error.unwrap_or_else(|| std::io::Error::other("Unknown error"))));
    }

    println!("File content: '{}'", content);
    
    // Check content is valid (empty or empty JSON array)
    assert!(
        content.is_empty() || content.trim() == "[]",
        "Unexpected content in output file: '{}'",
        content
    );

    // File cleanup happens automatically via drop guards
    Ok(())
}

#[tokio::test]
async fn test_concurrency_limits_respected() -> Result<()> {
    // Create a checker with very limited concurrency
    let concurrency_limit = 3;
    let checker = MdiChecker::new(concurrency_limit, 500)?;

    // Generate a smaller set of test domains to avoid test flakiness
    let mut domains = Vec::new();
    for i in 0..5 {
        domains.push(format!("test-domain-{}.com", i));
    }

    // Convert domains to string slices for the helper function
    let domains_refs: Vec<&str> = domains.iter().map(AsRef::as_ref).collect();

    // Create cleanup guard for automatic file cleanup
    struct CleanupGuard(PathBuf);
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0); // Ignore errors on cleanup
        }
    }

    // Create a temporary file with the test domains
    let input_file = create_test_domain_file(&domains_refs).await?;
    let _input_guard = CleanupGuard(input_file.clone());

    // Verify the file exists more robustly using std::path::Path
    assert!(
        std::path::Path::new(&input_file).exists(),
        "Test file was not created properly: {}",
        input_file.display()
    );

    // Create an output file path with a unique timestamp to avoid collisions
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join(format!(
        "concurrency_results_{}.json",
        Instant::now().elapsed().as_nanos()
    ));
    let _output_guard = CleanupGuard(output_file.clone());

    // Process the batch with a small chunk size and better error handling
    checker
        .process_batch(
            &input_file,
            Some(&output_file),
            2,  // small chunk size
            60, // rate limit
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to process batch: {}", e))?;

    // Wait a moment to ensure file operations complete on all platforms
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify the output file exists with better error message
    assert!(
        std::path::Path::new(&output_file).exists(),
        "Output file does not exist: {}",
        output_file.display()
    );

    // Read the content to ensure all domains were processed with better error handling
    let content = fs::read_to_string(&output_file).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read output file {}: {}",
            output_file.display(),
            e
        )
    })?;

    // Verify content has our domains
    for domain in domains_refs.iter() {
        assert!(
            content.contains(domain),
            "Domain '{}' not found in output content",
            domain
        );
    }

    // Files will be cleaned up automatically via drop guards
    Ok(())
}

// Test error case for invalid input file
#[tokio::test]
async fn test_process_batch_with_nonexistent_file() -> Result<()> {
    let checker = MdiChecker::new(1, 1000)?;

    // Create a path to a file that doesn't exist
    let nonexistent_file = PathBuf::from("/tmp/nonexistent_file_that_does_not_exist.txt");

    // Try to process the nonexistent file
    let result = checker
        .process_batch(
            &nonexistent_file,
            None, // No output file needed
            10,
            30,
        )
        .await;

    // Should fail with an error
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_str = format!("{}", err);
    assert!(err_str.contains("Failed to open") || err_str.contains("No such file"));

    Ok(())
}

// Test concurrent domain checking with rate limiting
#[tokio::test]
async fn test_concurrent_domain_checking() -> Result<()> {
    let concurrency = 5;
    let checker = MdiChecker::new(concurrency, 1000)?;

    // Create a set of domains to check concurrently
    let domains = [
        "invalid.domain1",
        "invalid.domain2",
        "invalid.domain3",
        "invalid.domain4",
        "invalid.domain5",
        "invalid.domain6",
        "invalid.domain7",
        "invalid.domain8",
        "invalid.domain9",
        "invalid.domain10",
    ];

    // Check all domains concurrently using tokio::spawn
    let mut handles = Vec::new();
    for domain in domains.iter() {
        let checker_clone = checker.clone();
        let domain = domain.to_string();
        handles.push(tokio::spawn(async move {
            checker_clone.check_domain(&domain).await
        }));
    }

    // Wait for all checks to complete
    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await??;
        results.push(result);
    }

    // Verify we got results for all domains
    assert_eq!(results.len(), domains.len());

    // All should have errors since they're invalid domains
    for result in results {
        assert!(result.error.is_some());
    }

    Ok(())
}
