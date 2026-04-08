#!/bin/bash
# On-Prem Network InfraIQ Version Management Script
# This script manages project versioning dynamically

# Get the script directory and navigate to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Version file paths
VERSION_JSON_PATH="$PROJECT_ROOT/Discovery/version.json"
DIRECTORY_BUILD_PROPS="$PROJECT_ROOT/Directory.Build.props"

# Function to display current version
show_version() {
    if [ -f "$VERSION_JSON_PATH" ]; then
        if command -v jq &> /dev/null; then
            local version=$(jq -r '.Tag // (.Major | tostring) + "." + (.Minor | tostring) + "." + (.Patch | tostring)' "$VERSION_JSON_PATH")
            local product=$(jq -r '.ProductName' "$VERSION_JSON_PATH")
            echo "Current Version: $product $version"
        else
            echo "Current version information requires jq to parse JSON"
            echo "Install jq: sudo apt-get install jq"
        fi
    elif [ -f "$DIRECTORY_BUILD_PROPS" ]; then
        local version=$(grep -o '<Version>[^<]*</Version>' "$DIRECTORY_BUILD_PROPS" | sed 's/<Version>\(.*\)<\/Version>/\1/')
        local product=$(grep -o '<Product>[^<]*</Product>' "$DIRECTORY_BUILD_PROPS" | sed 's/<Product>\(.*\)<\/Product>/\1/')
        echo "Current Version: $product $version"
    else
        echo "❌ Error: No version files found"
        exit 1
    fi
}

# Function to update version in version.json
update_version_json() {
    local major=$1
    local minor=$2
    local patch=$3
    local prerelease=$4
    
    if command -v jq &> /dev/null; then
        local tag="v$major.$minor.$patch"
        if [ -n "$prerelease" ]; then
            tag="$tag-$prerelease"
        fi
        
        # Update version.json using jq
        jq --arg major "$major" \
           --arg minor "$minor" \
           --arg patch "$patch" \
           --arg prerelease "$prerelease" \
           --arg tag "$tag" \
           --arg date "$(date -u +%Y-%m-%dT%H:%M:%S.%7NZ)" \
           --arg commit "$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
           --arg release_date "$(date -u +%Y-%m-%d)" \
           '.Major = ($major | tonumber) |
            .Minor = ($minor | tonumber) |
            .Patch = ($patch | tonumber) |
            .PreRelease = (if $prerelease == "" then null else $prerelease end) |
            .Tag = $tag |
            .LastUpdated = $date |
            .LastCommitHash = $commit |
            .BuildNumber = (.BuildNumber + 1) |
            .ReleaseDate = $release_date' \
           "$VERSION_JSON_PATH" > "$VERSION_JSON_PATH.tmp" && mv "$VERSION_JSON_PATH.tmp" "$VERSION_JSON_PATH"
        
        echo "✅ Updated version.json to $tag"
    else
        echo "❌ Error: jq is required to update version.json"
        echo "Install jq: sudo apt-get install jq"
        exit 1
    fi
}

# Function to update version in Directory.Build.props
update_directory_build_props() {
    local version=$1
    
    # Update Directory.Build.props
    sed -i "s|<Version>.*</Version>|<Version>$version</Version>|" "$DIRECTORY_BUILD_PROPS"
    sed -i "s|<AssemblyVersion>.*</AssemblyVersion>|<AssemblyVersion>$version.0</AssemblyVersion>|" "$DIRECTORY_BUILD_PROPS"
    sed -i "s|<FileVersion>.*</FileVersion>|<FileVersion>$version.0</FileVersion>|" "$DIRECTORY_BUILD_PROPS"
    
    echo "✅ Updated Directory.Build.props to $version"
}

# Function to bump version
bump_version() {
    local bump_type=$1
    
    if [ ! -f "$VERSION_JSON_PATH" ]; then
        echo "❌ Error: version.json not found"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        echo "❌ Error: jq is required for version bumping"
        echo "Install jq: sudo apt-get install jq"
        exit 1
    fi
    
    local current_major=$(jq -r '.Major' "$VERSION_JSON_PATH")
    local current_minor=$(jq -r '.Minor' "$VERSION_JSON_PATH")
    local current_patch=$(jq -r '.Patch' "$VERSION_JSON_PATH")
    
    case $bump_type in
        "major")
            update_version_json $((current_major + 1)) 0 0 ""
            update_directory_build_props "$((current_major + 1)).0.0"
            ;;
        "minor")
            update_version_json $current_major $((current_minor + 1)) 0 ""
            update_directory_build_props "$current_major.$((current_minor + 1)).0"
            ;;
        "patch")
            update_version_json $current_major $current_minor $((current_patch + 1)) ""
            update_directory_build_props "$current_major.$current_minor.$((current_patch + 1))"
            ;;
        *)
            echo "❌ Error: Invalid bump type. Use 'major', 'minor', or 'patch'"
            exit 1
            ;;
    esac
}

# Function to set specific version
set_version() {
    local version=$1
    
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-.*)?$ ]]; then
        echo "❌ Error: Invalid version format. Use semantic versioning (e.g., 1.2.3 or 1.2.3-alpha)"
        exit 1
    fi
    
    # Parse version components
    local version_without_prerelease=${version%-*}
    local prerelease=""
    if [[ $version == *"-"* ]]; then
        prerelease=${version#*-}
    fi
    
    IFS='.' read -ra VERSION_PARTS <<< "$version_without_prerelease"
    local major=${VERSION_PARTS[0]}
    local minor=${VERSION_PARTS[1]}
    local patch=${VERSION_PARTS[2]}
    
    update_version_json $major $minor $patch "$prerelease"
    update_directory_build_props "$major.$minor.$patch"
}

# Function to create git tag
create_tag() {
    if [ ! -f "$VERSION_JSON_PATH" ]; then
        echo "❌ Error: version.json not found"
        exit 1
    fi
    
    if command -v jq &> /dev/null; then
        local tag=$(jq -r '.Tag' "$VERSION_JSON_PATH")
        local product=$(jq -r '.ProductName' "$VERSION_JSON_PATH")
        
        echo "Creating git tag: $tag"
        git tag -a "$tag" -m "Release $product $tag"
        
        echo "✅ Git tag '$tag' created successfully"
        echo "📝 To push tag: git push origin $tag"
    else
        echo "❌ Error: jq is required to read version information"
        exit 1
    fi
}

# Main script logic
case "${1:-}" in
    "show")
        show_version
        ;;
    "bump")
        if [ -z "${2:-}" ]; then
            echo "Usage: $0 bump <major|minor|patch>"
            exit 1
        fi
        bump_version "$2"
        show_version
        ;;
    "set")
        if [ -z "${2:-}" ]; then
            echo "Usage: $0 set <version>"
            echo "Example: $0 set 2.1.0"
            echo "Example: $0 set 2.1.0-alpha"
            exit 1
        fi
        set_version "$2"
        show_version
        ;;
    "tag")
        create_tag
        ;;
    "release")
        # Run the release script
        exec "$SCRIPT_DIR/release.sh"
        ;;
    *)
        echo "🔧 On-Prem Network InfraIQ Version Manager"
        echo "=============================================="
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  show                 Display current version"
        echo "  bump <type>          Bump version (major|minor|patch)"
        echo "  set <version>        Set specific version (e.g., 2.1.0 or 2.1.0-alpha)"
        echo "  tag                  Create git tag for current version"
        echo "  release              Run release preparation script"
        echo ""
        echo "Examples:"
        echo "  $0 show              # Show current version"
        echo "  $0 bump patch        # Increment patch version"
        echo "  $0 set 3.0.0         # Set version to 3.0.0"
        echo "  $0 tag               # Create git tag"
        echo "  $0 release           # Prepare release"
        echo ""
        show_version
        ;;
esac
