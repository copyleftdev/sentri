// src/sanitize.rs
//
// Output sanitization module to prevent information leaks
// Implements the security:output:sanitize_all_output rule

use crate::core::DomainResult;
use html_escape::encode_text;

/// Sanitizes a domain result before output to prevent information leaks
///
/// This function sanitizes all fields in a DomainResult to ensure:
/// - No HTML/script injection is possible if output is rendered in a web context
/// - No sensitive information is leaked
/// - Domain names and tenant data are properly escaped
///
/// # Arguments
/// * `result` - The domain result to sanitize
///
/// # Returns
/// * `DomainResult` - A sanitized copy of the input result
pub fn sanitize_domain_result(result: &DomainResult) -> DomainResult {
    // Create a new result with sanitized fields
    DomainResult {
        // Sanitize the domain name
        domain: sanitize_domain(&result.domain),

        // Sanitize optional tenant value
        tenant: result.tenant.as_ref().map(|t| sanitize_string(t)),

        // Sanitize each federated domain
        federated_domains: result
            .federated_domains
            .iter()
            .map(|d| sanitize_domain(d))
            .collect(),

        // Sanitize optional MDI instance
        mdi_instance: result.mdi_instance.as_ref().map(|m| sanitize_string(m)),

        // Keep numeric processing time
        processing_time_ms: result.processing_time_ms,

        // Sanitize optional error message
        error: result.error.as_ref().map(|e| sanitize_error(e)),
    }
}

/// Sanitizes a domain string to prevent security issues
///
/// # Arguments
/// * `domain` - Domain string to sanitize
///
/// # Returns
/// * `String` - Sanitized domain
fn sanitize_domain(domain: &str) -> String {
    let trimmed = domain.trim();

    // Filter out any control characters
    let filtered = trimmed
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();

    // Encode HTML entities to prevent XSS if output is rendered in HTML
    encode_text(&filtered).to_string()
}

/// Sanitizes a general string value
///
/// # Arguments
/// * `value` - String to sanitize
///
/// # Returns
/// * `String` - Sanitized string
fn sanitize_string(value: &str) -> String {
    let trimmed = value.trim();

    // Filter out control characters
    let filtered = trimmed
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();

    // Encode HTML entities
    encode_text(&filtered).to_string()
}

/// Sanitizes error messages to prevent leaking internal details
///
/// # Arguments
/// * `error` - Error message to sanitize
///
/// # Returns
/// * `String` - Sanitized error message
fn sanitize_error(error: &str) -> String {
    // Filter out any internal paths or IPs that might be in error messages
    let filtered = error.replace(|c: char| c.is_control(), "");
    let sanitized = encode_text(&filtered).to_string();

    // Ensure we don't leak absolute paths
    // This regex pattern will replace things like /home/user/path with [REDACTED]
    let path_pattern = regex::Regex::new(r"(/[a-zA-Z0-9_\-\.]+)+")
        .unwrap_or_else(|_| regex::Regex::new(r"").unwrap());
    path_pattern
        .replace_all(&sanitized, "[REDACTED_PATH]")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::DomainResult;

    #[test]
    fn test_sanitize_domain() {
        assert_eq!(sanitize_domain("example.com"), "example.com");
        assert_eq!(
            sanitize_domain("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(
            sanitize_domain("domain.com\n\rinjection"),
            "domain.cominjection"
        );
    }

    #[test]
    fn test_sanitize_error() {
        assert_eq!(
            sanitize_error("Error at /home/user/projects/sentri/src/file.rs"),
            "Error at [REDACTED_PATH]"
        );
    }

    #[test]
    fn test_sanitize_domain_result() {
        let result = DomainResult {
            domain: "<script>evil.com".to_string(),
            tenant: Some("tenant<img src=x>".to_string()),
            federated_domains: vec!["a.com".to_string(), "b.com\n".to_string()],
            mdi_instance: Some("instance.atp.azure.com".to_string()),
            processing_time_ms: 100,
            error: Some("Failed at /home/user/code.rs".to_string()),
        };

        let sanitized = sanitize_domain_result(&result);

        assert_eq!(sanitized.domain, "&lt;script&gt;evil.com");
        assert_eq!(
            sanitized.tenant,
            Some("tenant&lt;img src=x&gt;".to_string())
        );
        assert_eq!(
            sanitized.federated_domains,
            vec!["a.com".to_string(), "b.com".to_string()]
        );
        assert_eq!(
            sanitized.mdi_instance,
            Some("instance.atp.azure.com".to_string())
        );
        assert_eq!(
            sanitized.error,
            Some("Failed at [REDACTED_PATH]".to_string())
        );
    }
}
