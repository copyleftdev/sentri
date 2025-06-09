#[path = "../src/validation.rs"]
mod validation;
use validation::{validate_domain, DomainValidator};

#[test]
fn test_valid_domain_formats() {
    let validator = DomainValidator::new();

    // Test valid domain formats
    assert!(validator.validate_domain_format("example.com"));
    assert!(validator.validate_domain_format("sub.example.com"));
    assert!(validator.validate_domain_format("sub-domain.example.co.uk"));
    assert!(validator.validate_domain_format("123.example.com"));
    assert!(validator.validate_domain_format("example-domain.com"));
}

#[test]
fn test_invalid_domain_formats() {
    let validator = DomainValidator::new();

    // Test invalid domain formats
    assert!(!validator.validate_domain_format("")); // Empty
    assert!(!validator.validate_domain_format(&"x".repeat(254))); // Too long
    assert!(!validator.validate_domain_format("example")); // No dot
    assert!(!validator.validate_domain_format("example.")); // Ends with dot
    assert!(!validator.validate_domain_format(".example.com")); // Starts with dot
    assert!(!validator.validate_domain_format("sub..example.com")); // Double dot
    assert!(!validator.validate_domain_format("-example.com")); // Starts with hyphen
    assert!(!validator.validate_domain_format("example-.com")); // Label ends with hyphen
    assert!(!validator.validate_domain_format("exam!ple.com")); // Invalid character
    assert!(!validator.validate_domain_format("example.c")); // TLD too short
    assert!(!validator.validate_domain_format(&("x".repeat(64) + ".com"))); // Label too long
}

#[test]
fn test_suspicious_domains() {
    let validator = DomainValidator::new();

    // Suspicious domains
    assert!(validator.is_suspicious("a-b-c-d-e-f.com")); // Too many hyphens
    assert!(validator.is_suspicious("example.abcdefghijklmn")); // Unusual TLD
    assert!(validator.is_suspicious("aaaaaaaaa.com")); // Repeating pattern

    // Non-suspicious domains
    assert!(!validator.is_suspicious("example.com"));
    assert!(!validator.is_suspicious("google.com"));
    assert!(!validator.is_suspicious("microsoft.com"));
}

#[test]
fn test_validate_domain_function() {
    // Valid domains should return Ok
    assert!(validate_domain("example.com").is_ok());
    assert!(validate_domain("sub.example.com").is_ok());

    // Invalid format should return Err with appropriate message
    let err = validate_domain("invalid..domain").unwrap_err();
    assert!(err.contains("Invalid domain format"));

    // Suspicious domains should return Err with appropriate message
    let err = validate_domain("a-b-c-d-e-f.com").unwrap_err();
    assert!(err.contains("Suspicious domain"));
}
