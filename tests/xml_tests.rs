use anyhow::Result;
use sentri::xml::XmlParser;

#[test]
fn test_xml_parser_creation() {
    let parser = XmlParser::new_test_mode();
    assert!(parser.create_federation_request("example.com").contains("example.com"));
    assert!(parser.create_federation_request("example.com").contains("GetFederationInformation"));
}

#[test]
fn test_federation_request_generation() {
    let parser = XmlParser::new_test_mode();
    let request = parser.create_federation_request("contoso.com");
    
    // Check for expected SOAP envelope and structure
    assert!(request.contains("soap:Envelope"));
    assert!(request.contains("soap:Body"));
    assert!(request.contains("GetFederationInformation"));
    assert!(request.contains("contoso.com"));
    assert!(request.contains("MessageID"));
}

#[test]
fn test_parse_federation_response_valid() -> Result<()> {
    let parser = XmlParser::new_test_mode();
    
    // Valid response with multiple domains
    let valid_response = r#"
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <GetFederationInformationResponse xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
                    <Domain>contoso.com</Domain>
                    <Domain>fabrikam.com</Domain>
                    <Domain>example.org</Domain>
                </Response>
            </GetFederationInformationResponse>
        </soap:Body>
    </soap:Envelope>
    "#;
    
    let federation_info = parser.parse_federation_response(valid_response)?;
    
    assert_eq!(federation_info.domains.len(), 3);
    assert!(federation_info.domains.contains(&"contoso.com".to_string()));
    assert!(federation_info.domains.contains(&"fabrikam.com".to_string()));
    assert!(federation_info.domains.contains(&"example.org".to_string()));
    
    Ok(())
}

#[test]
fn test_parse_federation_response_with_different_namespace() -> Result<()> {
    let parser = XmlParser::new_test_mode();
    
    // Valid response with a different but acceptable namespace
    let valid_response = r#"
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <GetFederationInformationResponse xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
                <Response xmlns:auto="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                    <auto:Domain>contoso.com</auto:Domain>
                </Response>
            </GetFederationInformationResponse>
        </soap:Body>
    </soap:Envelope>
    "#;
    
    let federation_info = parser.parse_federation_response(valid_response)?;
    
    assert_eq!(federation_info.domains.len(), 1);
    assert!(federation_info.domains.contains(&"contoso.com".to_string()));
    
    Ok(())
}

#[test]
fn test_parse_federation_response_invalid_empty() {
    let parser = XmlParser::new_test_mode();
    
    // Empty content
    let result = parser.parse_federation_response("");
    assert!(result.is_err());
    
    // Content with no SOAP structure
    let result = parser.parse_federation_response("<random>data</random>");
    assert!(result.is_err());
}

#[test]
fn test_parse_federation_response_invalid_structure() {
    let parser = XmlParser::new_test_mode();
    
    // Missing required elements
    let invalid_response = r#"
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <SomeOtherElement>
                <Text>No federation data here</Text>
            </SomeOtherElement>
        </soap:Body>
    </soap:Envelope>
    "#;
    
    let result = parser.parse_federation_response(invalid_response);
    assert!(result.is_err());
}

#[test]
fn test_parse_federation_response_no_domains() {
    let parser = XmlParser::new_test_mode();
    
    // Response with required structure but no domain elements
    let no_domains_response = r#"<!-- test_parse_federation_response_no_domains -->
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <GetFederationInformationResponse xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
                    <!-- No domain elements -->
                </Response>
            </GetFederationInformationResponse>
        </soap:Body>
    </soap:Envelope>
    "#;
    
    let result = parser.parse_federation_response(no_domains_response);
    assert!(result.is_err());
}

#[test]
fn test_parse_federation_response_with_invalid_domains() -> Result<()> {
    let parser = XmlParser::new_test_mode();
    
    // Contains both valid and invalid domains
    let mixed_domains_response = r#"<!-- test_parse_federation_response_with_invalid_domains -->
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <GetFederationInformationResponse xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
                    <Domain>valid-domain.com</Domain>
                    <Domain>invalid..domain</Domain>
                    <Domain>another.valid.domain.org</Domain>
                </Response>
            </GetFederationInformationResponse>
        </soap:Body>
    </soap:Envelope>
    "#;
    
    let federation_info = parser.parse_federation_response(mixed_domains_response)?;
    
    // Only the valid domains should be included
    assert_eq!(federation_info.domains.len(), 2);
    assert!(federation_info.domains.contains(&"valid-domain.com".to_string()));
    assert!(federation_info.domains.contains(&"another.valid.domain.org".to_string()));
    assert!(!federation_info.domains.contains(&"invalid..domain".to_string()));
    
    Ok(())
}
