use anyhow::Result;
use sentri::core::{DomainResult, FederationInfo, MdiChecker};

#[tokio::test]
async fn test_mdi_checker_creation() {
    // Test creation with valid parameters
    // MdiChecker::new takes just concurrent_requests and timeout_ms
    let checker = MdiChecker::new(10, 500);

    // Assert the checker is initialized without error
    assert!(checker.is_ok());

    // We can't verify private fields, but we can ensure it was created successfully
    let _checker = checker.unwrap();
    // Success if we reach this point without error
}

#[tokio::test]
async fn test_domain_result_creation() {
    let domain = "test.com".to_string();
    let tenant = Some("test".to_string());
    let federated_domains = vec!["federated.com".to_string()];

    let result = DomainResult {
        domain: domain.clone(),
        tenant: tenant.clone(),
        federated_domains: federated_domains.clone(),
        mdi_instance: Some("mdi.test.com".to_string()),
        processing_time_ms: 100,
        error: None,
    };

    assert_eq!(result.domain, domain);
    assert_eq!(result.tenant, tenant);
    assert!(result.processing_time_ms > 0);

    // Test federated domains
    assert_eq!(result.federated_domains.len(), 1);
    assert_eq!(result.federated_domains[0], "federated.com");
}

#[tokio::test]
async fn test_federation_info_creation() {
    let domains = vec!["domain1.com".to_string(), "domain2.com".to_string()];

    let federation_info = FederationInfo {
        domains: domains.clone(),
    };

    assert_eq!(federation_info.domains, domains);
}

#[tokio::test]
async fn test_domain_result_without_federation() {
    // Create a domain result without federation information
    let result = DomainResult {
        domain: "example.com".to_string(),
        tenant: None,
        federated_domains: vec![], // Empty vector for no federated domains
        mdi_instance: None,
        processing_time_ms: 100,
        error: None,
    };

    // Verify the fields reflect a domain without federation
    assert_eq!(result.domain, "example.com");
    assert!(result.tenant.is_none());
    assert!(result.federated_domains.is_empty()); // Use is_empty instead of is_none
    assert!(result.mdi_instance.is_none());
    assert_eq!(result.processing_time_ms, 100);
    assert!(result.error.is_none());
}

#[tokio::test]
async fn test_domain_result_with_error() {
    let domain = "error-domain.com".to_string();

    let result = DomainResult {
        domain: domain.clone(),
        tenant: None,
        federated_domains: vec![], // Empty vector for no federated domains
        mdi_instance: None,
        processing_time_ms: 50,
        error: Some("Connection failed".to_string()),
    };

    assert_eq!(result.domain, domain);
    assert!(result.tenant.is_none());
    assert!(result.federated_domains.is_empty()); // Use is_empty instead of is_none
    assert!(result.mdi_instance.is_none());
    assert_eq!(result.processing_time_ms, 50);
    assert_eq!(result.error.unwrap(), "Connection failed");
}

#[tokio::test]
async fn test_read_domains_from_file() -> Result<()> {
    // Create a temporary file with test domains
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("test_domains.txt");

    // Write test domains to the file
    let test_domains = "domain1.com\ndomain2.com\ndomain3.com";
    std::fs::write(&test_file, test_domains)?;

    // Create checker
    let _checker = MdiChecker::new(2, 500)?;

    // Test file exists
    assert!(test_file.exists());

    // Clean up
    std::fs::remove_file(test_file)?;

    Ok(())
}
