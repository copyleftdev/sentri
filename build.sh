#!/bin/bash

# High-performance build script for Sentri
set -euo pipefail

echo "Building Sentri with maximum optimizations..."

# Clean previous builds
cargo clean

# Set optimization flags
export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat -C codegen-units=1"

# Build with release optimizations
cargo build --release

echo "Build completed successfully!"
echo "Binary location: target/release/sentri"

# Verify the build
if [ -f "target/release/sentri" ]; then
    echo "✓ Binary created successfully"
    
    # Show binary size
    size=$(du -h target/release/sentri | cut -f1)
    echo "Binary size: $size"
    
    # Test basic functionality
    echo "Testing basic functionality..."
    ./target/release/sentri --help > /dev/null
    echo "✓ Basic functionality test passed"
else
    echo "✗ Build failed - binary not found"
    exit 1
fi

echo "Ready for high-performance domain checking!"
echo ""
echo "Example usage:"
echo "  Single domain: ./target/release/sentri single -d example.com"
echo "  Batch process: ./target/release/sentri batch -i domains.txt -o results.jsonl"