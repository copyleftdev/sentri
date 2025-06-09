# Sentri - MDI Instance Detection Tool

A secure, efficient Rust implementation for enumerating valid Microsoft 365 domains, retrieving tenant names, and checking for Microsoft Defender for Identity (MDI) instances.

## Features

- HTTPS certificate validation with secure defaults
- TLS 1.2+ enforcement for all connections
- Connection pooling with configurable idle timeout
- Configurable redirect limits
- Rate limiting for Microsoft API compliance
- Comprehensive input validation
- Parallel processing for batch operations
- Streaming I/O for memory-efficient processing of large files

## Usage

Sentri supports both single domain checks and batch processing from files:

### Single Domain Check

```bash
# Check a single domain
sentri single --domain example.com
```

### Batch Processing

```bash
# Process domains from a file (one per line)
sentri batch --input domains.txt --output results.json
```

### Global Options

These options can be used with any command:

```
-c, --concurrent <NUM>    Maximum concurrent requests [default: 5]
-t, --timeout <MS>        Request timeout in milliseconds [default: 5000]
-h, --help                Print help
-V, --version             Print version
```

### Full Command Reference

#### Single Domain Check

```
sentri single --domain <DOMAIN>

Options:
  -d, --domain <DOMAIN>   Domain to check (e.g., example.com)
  -h, --help              Print help
```

#### Batch Processing

```
sentri batch [OPTIONS]

Options:
  -i, --input <FILE>      Input file with domains, one per line
  -o, --output <FILE>     Output file for results (JSON)
  -s, --chunk-size <NUM>  Number of domains to process in each chunk [default: 50]
  -r, --rate-limit <NUM>  Maximum requests per minute [default: 30]
  -h, --help              Print help
```

## Examples

### Check a Single Domain

```bash
sentri -c 1 -t 10000 single --domain example.com
```

Example output:
```json
{
  "domain": "example.com",
  "tenant": "exampletenant",
  "federated_domains": [
    "example.com",
    "example.onmicrosoft.com"
  ],
  "mdi_instance": "exampletenantsensorapi.atp.azure.com",
  "processing_time_ms": 123,
  "error": null
}
```

### Process Multiple Domains from File

```bash
sentri -c 10 batch --input domains.txt --output results.json --chunk-size 100 --rate-limit 60
```

## Development

### Building

```bash
cargo build --release
```

### Testing

```bash
cargo test
```

## Security Features

- Certificate validation enabled by default
- Limited redirect following (max 5 by default)
- TLS 1.2+ enforcement
- Proper error handling that doesn't expose internals
- Secure defaults according to industry best practices
- Timeouts on all network requests
- Configurable idle timeout for connection pools

## Error Handling

Errors are captured in structured JSON output for easy parsing:

```json
{
  "domain": "invalid-domain.example",
  "tenant": null,
  "federated_domains": [],
  "mdi_instance": null,
  "processing_time_ms": 5,
  "error": "Domain validation failed: Invalid domain format"
}
```

## Project Status

For latest development updates and task status, refer to the TODO.md file.
