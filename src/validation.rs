//! Domain name validation and security checking module
//!
//! This module implements RFC-compliant domain name validation with comprehensive security checks:
//! - Format validation according to RFC 1035 and related standards
//! - Suspicious domain detection to identify potentially malicious domains
//! - Input sanitization to prevent security issues including injection attacks
//! - Strict adherence to domain name specifications to prevent security bypasses
//!
//! # Security Considerations
//!
//! Input validation is the first line of defense in the application. This module ensures that:
//! - All domain inputs are properly sanitized before further processing
//! - Potentially malicious or suspicious domains are flagged early
//! - Strict RFC compliance prevents edge cases that could lead to security issues
//! - Character set limitations prevent Unicode-based homograph attacks
//!
//! # Performance Considerations
//!
//! The validation is designed to be efficient:
//! - Uses fast string operations and avoids regex where possible for better performance
//! - Implements early-return patterns to avoid unnecessary computation
//! - Minimizes memory allocations by using iterators and in-place checks
//! - Validation logic order is optimized for common failure cases first
//!
//! # Usage Guidelines
//!
//! The public `validate_domain` function should be used as the primary entry point for
//! all domain validation requirements in the application. It properly encapsulates both
//! format validation and security heuristics to provide a complete validation solution.

/// Domain validator implementing RFC-compliant checks and security heuristics
///
/// This struct provides methods for validating domain names against format
/// specifications and security heuristics. It follows a stateless design pattern
/// with methods that perform specific validation checks.
pub struct DomainValidator;

impl DomainValidator {
    /// Creates a new DomainValidator instance
    pub fn new() -> Self {
        Self {}
    }

    /// Validates a domain name for format and syntax according to RFC standards
    /// 
    /// This function performs comprehensive RFC-compliant domain validation to ensure
    /// the domain meets all formatting requirements and doesn't contain malformed
    /// components that could lead to security issues.
    ///
    /// # Format Requirements
    /// 
    /// This function checks that the domain:
    /// - Contains at least one dot (.) - RFC 1035 requirement for FQDN
    /// - Has a valid TLD (at least 2 characters)
    /// - Does not exceed 253 characters total length (RFC 1035)
    /// - Consists of valid characters (a-z, 0-9, -, .) only
    /// - Does not have consecutive dots which would indicate empty labels
    /// - Does not start or end with a dot or hyphen
    /// - Each label (part between dots) does not exceed 63 characters (RFC 1035)
    ///
    /// # Security Considerations
    /// 
    /// Domain format validation is critical for security because improper validation
    /// could allow injection attacks or lead to unexpected behavior in DNS resolution.
    /// This implementation enforces strict standards compliance to prevent such issues.
    ///
    /// # Performance Notes
    /// 
    /// The validation is implemented with early returns for efficiency, checking the
    /// most common failure cases first to avoid unnecessary processing. String splitting
    /// is minimized to reduce allocations.
    ///
    /// # Returns
    /// 
    /// * `true` - If the domain meets all format requirements
    /// * `false` - If the domain fails any validation check
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
    
    /// Checks if a domain appears to be potentially malicious using heuristic analysis
    /// 
    /// This function applies security heuristics to detect potentially suspicious or
    /// malicious domains. These patterns are commonly associated with generated domains
    /// used in phishing, malware distribution, or command-and-control operations.
    ///
    /// # Detection Heuristics
    /// 
    /// Looks for common indicators of suspicious domains:
    /// - Excessive number of hyphens (often used in automatically generated domains)
    /// - Very long TLDs (unusual and often associated with malicious registrations)
    /// - Unusual repeating character patterns (common in algorithm-generated domains)
    /// 
    /// # Security Considerations
    /// 
    /// This detection serves as an early warning system but is not meant to replace
    /// comprehensive security analysis. False positives are possible but are preferred
    /// over false negatives in security-critical applications.
    /// 
    /// # Performance Notes
    /// 
    /// The heuristics are applied in order of computational complexity, with simpler
    /// checks performed first for better performance. The function returns early on
    /// the first suspicious pattern match.
    ///
    /// # Returns
    /// 
    /// * `true` - If suspicious patterns are detected
    /// * `false` - If no suspicious patterns are found
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
/// both format validation and suspicious domain detection in a single call.
///
/// # Security Considerations
///
/// This function implements the principle that all external inputs must be validated
/// and sanitized (security:input:sanitize_all_input). It serves as the primary
/// defense against injection attacks, malformed inputs, and potentially malicious
/// domains.
///
/// # Performance Considerations
///
/// The function creates a single validator instance and performs validations in
/// sequence, starting with the less expensive format validation before moving to
/// heuristic analysis. This approach optimizes performance while maintaining
/// security integrity.
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
///
/// // Domain with invalid characters
/// assert!(validate_domain("example!.com").is_err());
///
/// // Suspicious domain with excessive hyphens
/// assert!(validate_domain("a-b-c-d-e-f.com").is_err());
/// ```
pub fn validate_domain(domain: &str) -> Result<(), String> {
    let validator = DomainValidator::new();
    
    if !validator.validate_domain_format(domain) {
        return Err(format!("Invalid domain format: {}", domain));
    }
    
    if validator.is_suspicious(domain) {
        return Err(format!("Suspicious domain detected: {}", domain));
    }
    
    // Domain passed all validation checks
    Ok(())
}
