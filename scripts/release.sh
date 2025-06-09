#!/bin/bash
# Sentri Release Script
# This script automates the release process for Sentri following the project standards
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 0.1.0

set -e

# Function documentation: Validate user has required tools installed
validate_environment() {
    # Check if gh CLI is installed
    if ! command -v gh &> /dev/null; then
        echo "ERROR: GitHub CLI (gh) is not installed. Please install it first:"
        echo "https://cli.github.com/manual/installation"
        exit 1
    fi

    # Check if user is authenticated with GitHub
    if ! gh auth status &> /dev/null; then
        echo "ERROR: You need to authenticate with GitHub first. Run:"
        echo "gh auth login"
        exit 1
    fi
}

# Function documentation: Prepare the repository for a release
prepare_release() {
    local version=$1

    # Ensure working directory is clean
    if [ -n "$(git status --porcelain)" ]; then
        echo "ERROR: Working directory is not clean. Commit or stash your changes first."
        exit 1
    fi

    # Update version in Cargo.toml
    sed -i "s/^version = \".*\"/version = \"$version\"/" Cargo.toml

    # Run tests to ensure everything works (follows verify_completion_with_tests rule)
    echo "Running tests to verify release quality..."
    cargo test --all-features
    
    # Run clippy to ensure code quality
    echo "Running clippy to ensure code quality..."
    cargo clippy --all-features -- -D warnings

    # Update documentation (follows update_todo_after_verification rule)
    echo "Updating TODO.md and documentation..."
    # Mark CI/CD setup as complete
    if grep -q "CI/CD pipeline setup" TODO.md; then
        sed -i "/CI\/CD pipeline setup/ s/🔄/✅/" TODO.md
        sed -i "/CI\/CD pipeline setup/ s/In progress/Completed with GitHub Actions/" TODO.md
    fi
}

# Function documentation: Create and push the release
create_release() {
    local version=$1
    local tag="v$version"

    # Commit the version changes
    git add Cargo.toml TODO.md
    git commit -m "Release v$version"

    # Create a tag
    git tag -a "$tag" -m "Release $tag"

    # Push to GitHub with rate limit awareness (follows rate_limit_domains rule)
    echo "Pushing changes to GitHub..."
    git push origin main
    sleep 2  # Small delay between operations to respect API limits
    git push origin "$tag"

    echo "✅ Release $tag created and pushed to GitHub."
    echo "🚀 GitHub Actions will now build and publish the release artifacts."
    echo "📝 You can check the progress at: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions"
}

# Main script execution
main() {
    # Check if version is provided
    if [ -z "$1" ]; then
        echo "ERROR: Version number is required."
        echo "Usage: ./scripts/release.sh <version>"
        echo "Example: ./scripts/release.sh 0.1.0"
        exit 1
    fi

    VERSION=$1

    validate_environment
    prepare_release "$VERSION"
    create_release "$VERSION"
}

# Execute the script with all arguments passed to it
main "$@"
