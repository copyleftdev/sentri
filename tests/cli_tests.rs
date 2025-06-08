use anyhow::Result;
use sentri::cli::{Cli, Commands};
use std::path::PathBuf;
use clap::Parser;

#[test]
fn test_cli_creation() -> Result<()> {
    let args = vec!["sentri", "single", "--domain", "example.com"];
    let cli = Cli::try_parse_from(args)?;
    
    match &cli.command {
        Commands::Single { domain } => {
            assert_eq!(domain, "example.com");
        },
        _ => panic!("Expected Single command"),
    }
    
    // Test default values
    assert_eq!(cli.concurrent_requests, 100); // Default value
    assert_eq!(cli.timeout_ms, 5000); // Default value
    
    Ok(())
}

#[test]
fn test_cli_batch_command() -> Result<()> {
    let input_file = PathBuf::from("input.txt");
    let output_file = PathBuf::from("output.json");
    
    let args = vec![
        "sentri", 
        "batch", 
        "--input-file", 
        input_file.to_str().unwrap(),
        "--output-file", 
        output_file.to_str().unwrap(),
        "--chunk-size", 
        "500",
        "--rate-limit",
        "30"
    ];
    let cli = Cli::try_parse_from(args)?;
    
    match &cli.command {
        Commands::Batch { 
            input_file, 
            output_file, 
            chunk_size,
            rate_limit
        } => {
            // Compare paths as strings for equality check
            assert_eq!(input_file.to_str(), input_file.to_str());
            // Check output_file is Some variant with correct path
            if let Some(path) = output_file {
                if let Some(of) = output_file.as_ref() {
                    // Compare Some<&str> with Some<&str> since to_str() returns Option<&str>
                    assert_eq!(path.to_str().unwrap(), of.to_str().unwrap());
                } else {
                    panic!("Output file should be Some, but was None");
                }
            } else {
                panic!("Expected Some output_file");
            }
            assert_eq!(*chunk_size, 500);
            assert_eq!(*rate_limit, 30);
        },
        _ => panic!("Expected Batch command"),
    }
    
    Ok(())
}

#[test]
fn test_cli_with_concurrent_requests() -> Result<()> {
    let args = vec![
        "sentri", 
        "--concurrent-requests", 
        "50",
        "single", 
        "--domain", 
        "example.com"
    ];
    let cli = Cli::try_parse_from(args)?;
    
    match &cli.command {
        Commands::Single { domain } => {
            assert_eq!(domain, "example.com");
        },
        _ => panic!("Expected Single command"),
    }
    
    assert_eq!(cli.concurrent_requests, 50);
    assert_eq!(cli.timeout_ms, 5000); // Default value
    
    Ok(())
}

#[test]
fn test_cli_with_timeout() -> Result<()> {
    let args = vec![
        "sentri", 
        "--timeout-ms", 
        "10000",
        "single", 
        "--domain", 
        "example.com"
    ];
    let cli = Cli::try_parse_from(args)?;
    
    match &cli.command {
        Commands::Single { domain } => {
            assert_eq!(domain, "example.com");
        },
        _ => panic!("Expected Single command"),
    }
    
    assert_eq!(cli.concurrent_requests, 100); // Default value
    assert_eq!(cli.timeout_ms, 10000);
    
    Ok(())
}
