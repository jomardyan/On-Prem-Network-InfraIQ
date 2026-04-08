# Release and Version Management Scripts

This directory contains scripts for managing releases and versioning for the On-Prem Network InfraIQ project.

## Scripts Overview

### 📋 `release.sh` - Dynamic Release Preparation
**Updated for dynamic versioning!** This script automatically detects the current project version and prepares a release with comprehensive information.

**Features:**
- **Dynamic Version Detection**: Automatically reads version from `version.json` or `Directory.Build.props`
- **Cross-platform JSON Parsing**: Works with or without `jq` utility
- **Comprehensive Build Validation**: Builds the solution and reports any issues
- **Dynamic Test Discovery**: Counts and reports test files automatically
- **Feature Listing**: Displays features from version configuration
- **Git Integration**: Shows current commit and branch information

**Usage:**
```bash
./release.sh
```

**Example Output:**
```
🚀 On-Prem Network InfraIQ v2.1.0 Release Preparation
=========================================================
📋 Version Information:
  • Version: 2.1.0
  • Product: On-Prem Network InfraIQ
  • Build Date: Wed Jul 16 16:02:40 UTC 2025
  • Commit: 9891f79
  • Branch: main

✅ Major Features Completed:
  • Web-based dashboard interface
  • Database result storage with Entity Framework
  • Enhanced IPv6 support with neighbor discovery
  • Cloud service integration (AWS, Azure, GCP)
  • Machine learning for anomaly detection
  • RESTful API with OpenAPI documentation
...
```

### 🔧 `version-manager.sh` - Version Management Utility
**New!** A comprehensive version management tool for the project.

**Features:**
- **Show Current Version**: Display current project version
- **Semantic Version Bumping**: Increment major, minor, or patch versions
- **Custom Version Setting**: Set specific version numbers
- **Git Tag Creation**: Automatically create and annotate git tags
- **File Synchronization**: Updates both `version.json` and `Directory.Build.props`
- **Build Number Tracking**: Automatically increments build numbers

**Usage:**
```bash
# Show current version
./version-manager.sh show

# Bump version types
./version-manager.sh bump major    # 2.1.0 -> 3.0.0
./version-manager.sh bump minor    # 2.1.0 -> 2.2.0
./version-manager.sh bump patch    # 2.1.0 -> 2.1.1

# Set specific version
./version-manager.sh set 3.0.0
./version-manager.sh set 3.0.0-alpha
./version-manager.sh set 3.0.0-beta.1

# Create git tag for current version
./version-manager.sh tag

# Run release preparation
./version-manager.sh release
```

## Version Configuration Files

### `Discovery/version.json`
The primary version configuration file containing detailed version information:

```json
{
  "Major": 2,
  "Minor": 1,
  "Patch": 0,
  "PreRelease": null,
  "Tag": "v2.1.0",
  "ProductName": "On-Prem Network InfraIQ",
  "Description": "Enterprise-grade on-premises network infrastructure intelligence...",
  "Features": [
    "Web-based dashboard interface",
    "Database result storage with Entity Framework",
    "Enhanced IPv6 support with neighbor discovery",
    "Cloud service integration (AWS, Azure, GCP)",
    "Machine learning for anomaly detection",
    "RESTful API with OpenAPI documentation",
    "Real-time scanning capabilities",
    "Professional enterprise-grade security assessment"
  ],
  "LastUpdated": "2025-01-27T12:00:00.0000000Z",
  "LastCommitHash": "a9c443e",
  "BuildNumber": 1,
  "ReleaseDate": "2025-01-27"
}
```

### `Directory.Build.props`
MSBuild properties file for .NET project versioning:

```xml
<Project>
  <PropertyGroup>
    <Version>2.1.0</Version>
    <AssemblyVersion>2.1.0.0</AssemblyVersion>
    <FileVersion>2.1.0.0</FileVersion>
    <Product>On-Prem Network InfraIQ</Product>
    <Description>Enterprise-grade on-premises network infrastructure intelligence...</Description>
    <Authors>On-Prem Network InfraIQ Team</Authors>
    <Copyright>Copyright © 2025</Copyright>
  </PropertyGroup>
</Project>
```

## Workflow Examples

### Standard Release Process
```bash
# 1. Develop features and commit changes
git add .
git commit -m "feat: implement new feature"

# 2. Bump version appropriately
./scripts/version-manager.sh bump minor

# 3. Prepare release
./scripts/release.sh

# 4. Create and push git tag
./scripts/version-manager.sh tag
git push origin v2.2.0

# 5. Continue with deployment process
```

### Pre-release Workflow
```bash
# Create pre-release version
./scripts/version-manager.sh set 3.0.0-alpha

# Test and validate
./scripts/release.sh

# Create pre-release tag
./scripts/version-manager.sh tag
git push origin v3.0.0-alpha

# Later, finalize release
./scripts/version-manager.sh set 3.0.0
./scripts/version-manager.sh tag
```

### Hotfix Process
```bash
# For urgent patches
./scripts/version-manager.sh bump patch

# Immediate release preparation
./scripts/release.sh

# Create and deploy
./scripts/version-manager.sh tag
git push origin v2.1.1
```

## Dependencies

### Required
- **Bash**: Scripts are written for Bash shell
- **Git**: Required for commit information and tagging
- **.NET 8.0**: For building the solution
- **Basic Unix utilities**: `grep`, `sed`, `find`, `wc`

### Optional but Recommended
- **jq**: For enhanced JSON parsing capabilities
  ```bash
  # Ubuntu/Debian
  sudo apt-get install jq
  
  # macOS
  brew install jq
  
  # Windows (via Chocolatey)
  choco install jq
  ```

## Migration from Static Versioning

The old `release-v2.0.0.sh` script has been replaced with the dynamic `release.sh` script. Key improvements:

**Before (Static):**
- Hardcoded version "2.0.0"
- Manual feature list maintenance
- Fixed test count reporting
- No version management capabilities

**After (Dynamic):**
- Automatic version detection from project files
- Dynamic feature list from configuration
- Automatic test discovery
- Comprehensive version management
- Cross-platform compatibility
- Fallback parsing without dependencies

## Troubleshooting

### Common Issues

**"jq: command not found"**
- Scripts work without jq but with reduced functionality
- Install jq for full feature support
- Fallback parsing is available for basic operations

**"Version files not found"**
- Ensure you're running scripts from the correct directory
- Verify `Discovery/version.json` and `Directory.Build.props` exist
- Check file permissions

**"Build failed"**
- Ensure .NET 8.0 SDK is installed
- Check for compilation errors in the codebase
- Verify all dependencies are restored

**Git operations fail**
- Ensure you're in a git repository
- Check git configuration and permissions
- Verify network connectivity for remote operations

### Script Debugging

Enable verbose output by adding `set -x` to the top of any script:
```bash
#!/bin/bash
set -x  # Enable debugging
# ... rest of script
```

## Contributing

When modifying these scripts:

1. **Test thoroughly** across different environments
2. **Maintain backward compatibility** where possible
3. **Update documentation** for any changes
4. **Follow the project's coding standards** from `.github/copilot-instructions.md`
5. **Ensure cross-platform compatibility** (Linux, macOS, Windows/WSL)

## Security Considerations

- Scripts validate input formats and ranges
- No sensitive information is logged or exposed
- Git operations require proper authentication
- File operations use safe patterns to prevent injection

---

*These scripts are part of the On-Prem Network InfraIQ project and follow enterprise-grade development practices.*
