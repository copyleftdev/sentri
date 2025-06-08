#!/bin/bash

# Performance benchmark script for Sentri
set -euo pipefail

BINARY="./target/release/sentri"
TEST_DOMAINS="example_domains.txt"
RESULTS_FILE="benchmark_results.jsonl"

echo "=== Sentri Performance Benchmark ==="
echo ""

# Ensure binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    echo "Please run ./build.sh first"
    exit 1
fi

# Create test domains file if it doesn't exist
if [ ! -f "$TEST_DOMAINS" ]; then
    echo "Creating test domains file..."
    cat > "$TEST_DOMAINS" << EOF
microsoft.com
google.com
amazon.com
apple.com
netflix.com
salesforce.com
adobe.com
oracle.com
ibm.com
dell.com
EOF
fi

# Clean previous results
rm -f "$RESULTS_FILE"

echo "Testing single domain performance..."
echo "Domain: microsoft.com"
time $BINARY single -d microsoft.com

echo ""
echo "=== Batch Processing Benchmarks ==="

# Test different concurrency levels
for concurrency in 10 50 100 200; do
    echo ""
    echo "Testing with concurrency: $concurrency"
    echo "Command: $BINARY -c $concurrency batch -i $TEST_DOMAINS -o $RESULTS_FILE"
    
    # Clean results file
    rm -f "$RESULTS_FILE"
    
    # Time the execution
    start_time=$(date +%s.%N)
    $BINARY -c $concurrency batch -i "$TEST_DOMAINS" -o "$RESULTS_FILE" --rate-limit 20
    end_time=$(date +%s.%N)
    
    # Calculate duration
    duration=$(echo "$end_time - $start_time" | bc -l)
    
    # Count processed domains
    domain_count=$(wc -l < "$TEST_DOMAINS")
    successful_count=$(grep -v '"error":' "$RESULTS_FILE" | wc -l)
    
    # Calculate throughput
    throughput=$(echo "scale=2; $successful_count / $duration" | bc -l)
    
    echo "Results:"
    echo "  Duration: ${duration}s"
    echo "  Domains processed: $successful_count/$domain_count"
    echo "  Throughput: ${throughput} domains/second"
    
    # Show sample result
    echo "  Sample result:"
    head -1 "$RESULTS_FILE" | jq '.'
done

echo ""
echo "=== Memory Usage Test ==="
echo "Testing memory efficiency with batch processing..."

# Use valgrind if available for memory analysis
if command -v valgrind &> /dev/null; then
    echo "Running memory analysis with valgrind..."
    valgrind --tool=massif --massif-out-file=massif.out \
        $BINARY batch -i "$TEST_DOMAINS" -o "$RESULTS_FILE" --rate-limit 10 2>/dev/null
    
    if command -v ms_print &> /dev/null; then
        echo "Peak memory usage:"
        ms_print massif.out | grep "MB"
        rm -f massif.out
    fi
else
    echo "Valgrind not available, skipping memory analysis"
fi

echo ""
echo "=== Performance Recommendations ==="
echo ""

# Calculate optimal settings based on system
cpu_cores=$(nproc)
optimal_concurrency=$((cpu_cores * 20))

echo "System detected: $cpu_cores CPU cores"
echo "Recommended settings for this system:"
echo "  Conservative: -c 50 --rate-limit 20"
echo "  Balanced:     -c 100 --rate-limit 50" 
echo "  Aggressive:   -c $optimal_concurrency --rate-limit 100"
echo ""
echo "For millions of domains:"
echo "  $BINARY -c $optimal_concurrency batch -i huge_list.txt -o results.jsonl --chunk-size 5000 --rate-limit 100"

echo ""
echo "Benchmark completed!"
echo "Results saved to: $RESULTS_FILE"