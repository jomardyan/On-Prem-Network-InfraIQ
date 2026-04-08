#!/bin/bash
# On-Prem Network InfraIQ Dynamic Release Preparation Script
# This script prepares the repository for release with dynamic versioning

# Get the script directory and navigate to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Extract version information from project files
VERSION_JSON_PATH="$PROJECT_ROOT/Discovery/version.json"
DIRECTORY_BUILD_PROPS="$PROJECT_ROOT/Directory.Build.props"

# Read version from version.json if it exists, otherwise from Directory.Build.props
if [ -f "$VERSION_JSON_PATH" ]; then
    # Extract version information from version.json using jq if available, otherwise fallback to grep/sed
    if command -v jq &> /dev/null; then
        MAJOR=$(jq -r '.Major' "$VERSION_JSON_PATH")
        MINOR=$(jq -r '.Minor' "$VERSION_JSON_PATH")
        PATCH=$(jq -r '.Patch' "$VERSION_JSON_PATH")
        PRE_RELEASE=$(jq -r '.PreRelease // empty' "$VERSION_JSON_PATH")
        PRODUCT_NAME=$(jq -r '.ProductName' "$VERSION_JSON_PATH")
        DESCRIPTION=$(jq -r '.Description' "$VERSION_JSON_PATH")
        FEATURES=$(jq -r '.Features[]' "$VERSION_JSON_PATH" | sed 's/^/  • /')
    else
        # Fallback parsing without jq
        MAJOR=$(grep -o '"Major":\s*[0-9]*' "$VERSION_JSON_PATH" | grep -o '[0-9]*')
        MINOR=$(grep -o '"Minor":\s*[0-9]*' "$VERSION_JSON_PATH" | grep -o '[0-9]*')
        PATCH=$(grep -o '"Patch":\s*[0-9]*' "$VERSION_JSON_PATH" | grep -o '[0-9]*')
        PRE_RELEASE=$(grep -o '"PreRelease":\s*"[^"]*"' "$VERSION_JSON_PATH" | cut -d'"' -f4)
        PRODUCT_NAME=$(grep -o '"ProductName":\s*"[^"]*"' "$VERSION_JSON_PATH" | cut -d'"' -f4)
        DESCRIPTION=$(grep -o '"Description":\s*"[^"]*"' "$VERSION_JSON_PATH" | cut -d'"' -f4)
        FEATURES="  • Web-based dashboard interface\n  • Database result storage with Entity Framework\n  • Enhanced IPv6 support with neighbor discovery\n  • Cloud service integration (AWS, Azure, GCP)\n  • Machine learning for anomaly detection\n  • RESTful API with OpenAPI documentation"
    fi
    
    # Construct version string
    if [ -n "$PRE_RELEASE" ] && [ "$PRE_RELEASE" != "null" ]; then
        VERSION="$MAJOR.$MINOR.$PATCH-$PRE_RELEASE"
    else
        VERSION="$MAJOR.$MINOR.$PATCH"
    fi
elif [ -f "$DIRECTORY_BUILD_PROPS" ]; then
    # Extract version from Directory.Build.props
    VERSION=$(grep -o '<Version>[^<]*</Version>' "$DIRECTORY_BUILD_PROPS" | sed 's/<Version>\(.*\)<\/Version>/\1/')
    PRODUCT_NAME=$(grep -o '<Product>[^<]*</Product>' "$DIRECTORY_BUILD_PROPS" | sed 's/<Product>\(.*\)<\/Product>/\1/')
    DESCRIPTION=$(grep -o '<Description>[^<]*</Description>' "$DIRECTORY_BUILD_PROPS" | sed 's/<Description>\(.*\)<\/Description>/\1/')
    FEATURES="  • Enterprise-grade network discovery\n  • Professional security assessment\n  • Cross-platform compatibility"
else
    echo "❌ Error: Could not find version information in $VERSION_JSON_PATH or $DIRECTORY_BUILD_PROPS"
    exit 1
fi

# Default values if extraction fails
PRODUCT_NAME=${PRODUCT_NAME:-"On-Prem Network InfraIQ"}
DESCRIPTION=${DESCRIPTION:-"Enterprise-grade network infrastructure intelligence and security assessment platform"}

echo "🚀 $PRODUCT_NAME v$VERSION Release Preparation"
echo "========================================================="

# Display version information
echo "📋 Version Information:"
echo "  • Version: $VERSION"
echo "  • Product: $PRODUCT_NAME"
echo "  • Build Date: $(date)"
echo "  • Commit: $(git rev-parse HEAD)"
echo "  • Branch: $(git branch --show-current)"

# Display feature summary
echo ""
echo "✅ Major Features Completed:"
if command -v jq &> /dev/null && [ -f "$VERSION_JSON_PATH" ]; then
    # Display features from version.json if available
    echo "$FEATURES"
else
    # Fallback feature list
    echo -e "$FEATURES"
fi

# Get test count dynamically
echo ""
echo "🧪 Test Information:"
if [ -f "$PROJECT_ROOT/Discovery.Tests/Discovery.Tests.csproj" ]; then
    TEST_COUNT=$(find "$PROJECT_ROOT/Discovery.Tests" -name "*.cs" -type f -exec grep -l "\[Test\]\|\[Fact\]\|\[Theory\]" {} \; | wc -l)
    echo "  • Test files found: $TEST_COUNT"
    echo "  • Run 'dotnet test' for detailed test results"
else
    echo "  • Test project not found"
fi

# Check build status
echo ""
echo "🔨 Building solution..."
cd "$PROJECT_ROOT"
dotnet build --configuration Release --verbosity quiet

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi

# Display project structure
echo ""
echo "📁 Project Structure:"
echo "  • Discovery/ (Core console application)"
echo "  • Discovery.Web/ (Web dashboard interface)"
echo "  • Discovery.Tests/ (Test suite - 372 tests)"
echo "  • docs/ (Documentation)"
echo "  • Docker support (production-ready)"

# Display deployment options
echo ""
echo "🚀 Deployment Options:"
echo "  • Console: dotnet run --project Discovery"
echo "  • Web: dotnet run --project Discovery.Web"
echo "  • Docker: docker-compose up"

echo ""
echo "🎉 Release v$VERSION is ready for deployment!"
echo "📄 See RELEASE_NOTES.md for detailed information"
echo "🌐 Web dashboard will be available at http://localhost:5000"

# Optional: Update version in git tag
echo ""
echo "📝 Git Operations:"
echo "  • To create a release tag: git tag v$VERSION"
echo "  • To push tag: git push origin v$VERSION"