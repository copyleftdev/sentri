//! Domain name validation and security checking module
//!
//! This module implements RFC-compliant domain name validation with security checks:
//! - Format validation according to RFC 1035 and related standards
//! - Suspicious domain detection to identify potentially malicious domains
//! - Input sanitization to prevent security issues
//!
//! The validation includes checking for proper domain syntax, length limitations,
//! character restrictions, and heuristic patterns that may indicate suspicious domains.

/// Domain validator implementing RFC-compliant checks and security heuristics
pub struct DomainValidator;

impl DomainValidator {
    /// Creates a new DomainValidator instance
    pub fn new() -> Self {
        Self {}
    }

    /// Validates a domain name for format and syntax
    /// 
    /// This function checks that the domain:
    /// - Contains at least one dot (.)
    /// - Has a valid TLD (at least 2 characters)
    /// - Does not exceed 253 characters (RFC 1035)
    /// - Consists of valid characters (a-z, 0-9, -, .)
    /// - Does not have consecutive dots
    /// - Does not start or end with a dot or hyphen
    /// - Each label (part between dots) does not exceed 63 characters
    pub fn validate_domain_format(&self, domain: &str) -> bool {
        // Check length constraints
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }

        // Must contain at least one dot
        if !domain.contains('.') {
            return false;
        }

        // Split by dots to check each label
        let labels: Vec<&str> = domain.split('.').collect();
        
        // TLD must be at least 2 characters
        if let Some(tld) = labels.last() {
            if tld.len() < 2 {
                return false;
            }
        } else {
            return false;
        }
        
        // Check each label
        for label in labels {
            // Each label must not exceed 63 characters
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            
            // Check for valid characters
            if !label.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '-'
            }) {
                return false;
            }
            
            // Labels cannot start or end with hyphen
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
        }
        
        true
    }
    
    /// Checks if a domain appears to be potentially malicious
    /// 
    /// Looks for common indicators of suspicious domains:
    /// - Excessive number of hyphens
    /// - Very long TLDs
    /// - Unusual character patterns
    pub fn is_suspicious(&self, domain: &str) -> bool {
        // Count hyphens (excessive hyphens can be suspicious)
        let hyphen_count = domain.chars().filter(|&c| c == '-').count();
        if hyphen_count > 4 {
            return true;
        }
        
        // Check for very long TLDs (can indicate generated domains)
        if let Some(tld) = domain.split('.').last() {
            if tld.len() > 10 {
                return true;
            }
        }
        
        // Check for unusual repeating patterns
        let chars: Vec<char> = domain.chars().collect();
        let mut repeating_count = 0;
        
        for i in 1..chars.len() {
            if chars[i] == chars[i-1] {
                repeating_count += 1;
                if repeating_count >= 3 {
                    return true;
                }
            } else {
                repeating_count = 0;
            }
        }
        
        false
    }
}

/// Validates a domain name against format rules and security checks
///
/// This is the main validation function that should be used by other modules
/// to ensure domains are properly validated before processing. It combines
/// both format validation and suspicious domain detection.
///
/// # Arguments
/// * `domain` - The domain name string to validate
///
/// # Returns
/// * `Result<(), String>` - Ok(()) if valid, or Err with descriptive message if invalid
///
/// # Examples
///
/// ```
/// use sentri::validation::validate_domain;
///
/// // Valid domain
/// assert!(validate_domain("example.com").is_ok());
///
/// // Invalid domain (missing TLD)
/// assert!(validate_domain("invalid").is_err());
///
/// // Invalid domain (consecutive dots)
/// assert!(validate_domain("invalid..domain").is_err());
/// ```
pub fn validate_domain(domain: &str) -> Result<(), String> {
    let validator = DomainValidator::new();
    
    if !validator.validate_domain_format(domain) {
        return Err(format!("Invalid domain format: {}", domain));
    }
    
    if validator.is_suspicious(domain) {
        return Err(format!("Suspicious domain detected: {}", domain));
    }
    
    Ok(())
}
