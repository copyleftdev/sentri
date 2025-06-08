use anyhow::Result;
use sentri::xml::XmlParser;
use quick_xml::events::Event;
use quick_xml::Reader;

#[test]
fn debug_auto_domain_xml() -> Result<()> {
    let parser = XmlParser::new_test_mode();
    
    // Here's the failing test case with prefixed domain
    let test_xml = r#"
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
    
    // Manual debug parsing to see what's happening
    println!("DEBUG: Starting manual XML parsing");
    let mut reader = Reader::from_str(test_xml);
    reader.trim_text(true);
    
    let mut buf = Vec::new();
    let mut in_domain = false;
    let mut found_domains = Vec::new();
    
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = e.name();
                let local_name = reader.decoder().decode(name.local_name().as_ref())?
                    .to_string();
                
                println!("DEBUG: Start element: tag={}, local={}", 
                         String::from_utf8_lossy(name.as_ref()),
                         local_name);
                
                if local_name == "Domain" {
                    println!("DEBUG: Found Domain element!");
                    in_domain = true;
                }
            },
            Ok(Event::Text(ref e)) => {
                let text = e.unescape()?.to_string();
                println!("DEBUG: Text content: '{}', in_domain={}", text, in_domain);
                
                if in_domain && !text.trim().is_empty() {
                    println!("DEBUG: Found domain text: {}", text.trim());
                    found_domains.push(text.trim().to_string());
                }
            },
            Ok(Event::End(ref e)) => {
                let name = e.name();
                let local_name = reader.decoder().decode(name.local_name().as_ref())?
                    .to_string();
                
                println!("DEBUG: End element: {}", String::from_utf8_lossy(name.as_ref()));
                
                if local_name == "Domain" {
                    in_domain = false;
                }
            },
            Ok(Event::Eof) => break,
            Err(e) => {
                println!("DEBUG: Error: {:?}", e);
                return Err(anyhow::Error::msg(format!("Error parsing XML: {:?}", e)));
            },
            _ => {},
        }
        buf.clear();
    }
    
    println!("DEBUG: Manual parsing found domains: {:?}", found_domains);
    
    // Now try with our parser
    match parser.parse_federation_response(test_xml) {
        Ok(federation_info) => {
            println!("DEBUG: XmlParser found domains: {:?}", federation_info.domains);
            
            // Check if we found the domain
            assert_eq!(federation_info.domains.len(), 1, "Expected to find 1 domain");
            assert!(federation_info.domains.contains(&"contoso.com".to_string()), 
                   "Expected to find contoso.com domain");
            
            Ok(())
        },
        Err(e) => {
            println!("DEBUG: XmlParser error: {:?}", e);
            Err(e)
        }
    }
}
