# GitHub Copilot Instructions for On-Prem Network InfraIQ

This document provides comprehensive guidance for GitHub Copilot to assist with the On-Prem Network InfraIQ project. Follow these instructions to ensure consistent, high-quality code contributions.

## 🎯 Project Overview

On-Prem Network InfraIQ is an enterprise-grade network discovery and security assessment platform built with C# and .NET 8.0. The project emphasizes:

- **Performance**: High-concurrency scanning with async/await patterns
- **Security**: Enterprise-grade vulnerability detection and assessment
- **Cross-platform**: Windows, Linux, and macOS compatibility
- **Professional**: Enterprise-ready with comprehensive error handling

## 🏗️ Architecture and Patterns

### Code Organization
```
Discovery/
├── Core/              # Core models, interfaces, and constants
├── Services/          # Business logic and scanning services
├── Display/           # User interface and console output
├── IO/               # Input/output operations and file handling
├── Security/         # Security-specific functionality
└── Tools/            # Utility tools and helpers
```

### Design Patterns to Follow
- **Dependency Injection**: Use constructor injection for services
- **Async/Await**: All I/O operations must be asynchronous
- **SOLID Principles**: Single responsibility, open/closed, etc.
- **Factory Pattern**: For creating scanner instances
- **Observer Pattern**: For real-time result updates

## 📝 Coding Standards

### Naming Conventions
```csharp
// Classes: PascalCase
public class NetworkScanner { }

// Methods: PascalCase
public async Task ScanNetworkAsync() { }

// Properties: PascalCase
public string HostName { get; set; }

// Fields: _camelCase (private)
private readonly IPortScanner _portScanner;

// Constants: UPPER_CASE
public const int DEFAULT_TIMEOUT = 5000;
```

### Documentation Requirements
```csharp
/// <summary>
/// Scans a network range for active hosts and open ports.
/// </summary>
/// <param name="networkRange">The CIDR notation network range to scan.</param>
/// <param name="cancellationToken">Token to cancel the operation.</param>
/// <returns>A collection of scan results.</returns>
public async Task<IEnumerable<ScanResult>> ScanNetworkAsync(
    string networkRange, 
    CancellationToken cancellationToken = default)
{
    // Implementation
}
```

### Error Handling Patterns
```csharp
try
{
    var result = await SomeNetworkOperationAsync();
    return result;
}
catch (SocketException ex)
{
    _logger.LogWarning("Network connection failed: {Message}", ex.Message);
    return null;
}
catch (OperationCanceledException)
{
    _logger.LogInformation("Operation was cancelled");
    throw;
}
catch (Exception ex)
{
    _logger.LogError(ex, "Unexpected error during network operation");
    throw;
}
```

## 🔧 Technical Guidelines

### Network Programming
- Always use `CancellationToken` for network operations
- Implement proper timeout handling (default: 5 seconds)
- Use connection pooling where appropriate
- Handle IPv4 and IPv6 addresses
- Implement rate limiting to prevent network flooding

### Performance Optimization
```csharp
// Use SemaphoreSlim for concurrency control
private readonly SemaphoreSlim _semaphore = new(200, 200);

// Efficient parallel processing
var tasks = targets.Select(async target =>
{
    await _semaphore.WaitAsync(cancellationToken);
    try
    {
        return await ScanTargetAsync(target, cancellationToken);
    }
    finally
    {
        _semaphore.Release();
    }
});

var results = await Task.WhenAll(tasks);
```

### Security Considerations
- Validate all user inputs
- Sanitize network addresses and port ranges
- Implement proper authentication for secure services
- Use secure random number generation
- Follow OWASP guidelines for security scanning

## 🧪 Testing Standards

### Unit Test Structure
```csharp
[Test]
public async Task ScanPortAsync_ValidPort_ReturnsTrue()
{
    // Arrange
    var scanner = new PortScanner(timeout: 1000);
    var ipAddress = IPAddress.Parse("127.0.0.1");
    
    // Act
    var result = await scanner.ScanPortAsync(ipAddress, 80);
    
    // Assert
    Assert.That(result, Is.True);
}
```

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end functionality
- **Performance Tests**: Scalability and efficiency
- **Security Tests**: Vulnerability assessment accuracy

## 🔒 Security Scanning Guidelines

### Vulnerability Detection
```csharp
public class VulnerabilityInfo
{
    public string Host { get; set; }
    public int Port { get; set; }
    public VulnerabilitySeverity Severity { get; set; }
    public string Title { get; set; }
    public string Description { get; set; }
    public string RecommendedFix { get; set; }
}
```

### Severity Classification
- **Critical**: Immediate security risk requiring urgent attention
- **High**: Significant security vulnerability
- **Medium**: Moderate security concern
- **Low**: Minor security issue or informational

## 🌐 Network Discovery Patterns

### Port Scanning Implementation
```csharp
public async Task<bool> ScanPortAsync(IPAddress ipAddress, int port, int timeout)
{
    if (port < 1 || port > 65535)
        throw new ArgumentOutOfRangeException(nameof(port));

    try
    {
        using var client = new TcpClient();
        var connectTask = client.ConnectAsync(ipAddress, port);
        var timeoutTask = Task.Delay(timeout);
        
        var completedTask = await Task.WhenAny(connectTask, timeoutTask);
        return completedTask == connectTask && client.Connected;
    }
    catch (SocketException)
    {
        return false;
    }
}
```

### Service Detection
- Use banner grabbing for service identification
- Implement protocol-specific detection (HTTP, SSH, FTP, etc.)
- Parse service headers and responses
- Maintain service signature database

## 📊 Data Models

### Core Models to Use
```csharp
public record ScanResult(
    IPAddress IpAddress,
    int Port,
    bool IsOpen,
    string ServiceName,
    long PingTime,
    string OperatingSystem,
    string ServerInfo,
    DateTime DiscoveredAt,
    string Country,
    string Hostname,
    bool IsVulnerable,
    string VulnerabilityInfo,
    string ServiceVersion
);
```

## 🎨 User Interface Guidelines

### Console Output Standards
- Use Spectre.Console for rich console output
- Implement color coding: Green (success), Red (critical), Yellow (warning)
- Provide progress indicators for long operations
- Use tables for structured data display
- Include keyboard shortcuts for interactive mode

### Real-time Updates
```csharp
// Use live display for real-time results
await AnsiConsole.Live(display)
    .AutoClear(false)
    .Overflow(VerticalOverflow.Ellipsis)
    .Cropping(VerticalOverflowCropping.Top)
    .StartAsync(async ctx =>
    {
        // Update display in real-time
    });
```

## 🚀 Performance Requirements

### Benchmarks to Meet
- Single host scan: < 5 seconds for 1000 ports
- Network range scan: < 30 seconds for /24 network (254 hosts)
- Memory usage: < 100MB for typical operations
- CPU utilization: Efficient multi-threading without overwhelming system

### Optimization Techniques
- Use connection pooling
- Implement adaptive timeout based on network conditions
- Cache DNS resolutions
- Use efficient data structures (ConcurrentBag, etc.)

## 🔄 Continuous Integration

### Build Requirements
- Must compile without warnings in Release mode
- All tests must pass
- Code coverage should maintain current levels (175+ tests)
- Cross-platform compatibility verified

### Code Quality
- Follow StyleCop rules (may have suppressions for specific cases)
- Use nullable reference types
- Implement proper disposal patterns
- Follow async/await best practices

## 📚 Dependencies and Libraries

### Approved Libraries
- **Spectre.Console**: Rich console output and user interface
- **System.Net**: Core networking functionality
- **Microsoft.Extensions.Logging**: Structured logging
- **NUnit**: Unit testing framework

### Guidelines for New Dependencies
- Prefer .NET standard libraries over third-party
- Ensure cross-platform compatibility
- Verify security and maintenance status
- Document usage and rationale

## 🎯 Common Scenarios

### Adding New Scan Type
1. Create interface in `Core/Interfaces/`
2. Implement service in `Services/Scanning/`
3. Add to menu in `Program.cs`
4. Create corresponding tests
5. Update documentation

### Enhancing Security Detection
1. Add new vulnerability patterns to `NetworkConstants`
2. Implement detection logic in `VulnerabilityScanner`
3. Add severity classification
4. Include remediation guidance
5. Test against known vulnerable services

## 🏁 Code Review Checklist

When suggesting or reviewing code:
- [ ] Follows async/await patterns consistently
- [ ] Includes proper error handling and logging
- [ ] Has comprehensive XML documentation
- [ ] Includes appropriate unit tests, framework Xunit
- [ ] Maintains cross-platform compatibility
- [ ] Follows established naming conventions
- [ ] Implements proper disposal of resources
- [ ] Uses appropriate data structures for performance
- [ ] Includes security considerations
- [ ] Maintains backward compatibility where possible

Remember: This is an enterprise-grade tool used by security professionals. Code quality, reliability, and security are paramount.

## 🔄 Latest Updates & Modern Practices

### Recent Project Enhancements (v1.1.0)
- **Real-time Live Display**: Enhanced interactive scanning with multi-view modes
- **Enhanced Vulnerability Detection**: 30+ vulnerability types with CVE integration
- **Router Security Assessment**: Specialized scanning for Cisco, MikroTik, enterprise devices
- **Industrial Protocol Support**: Modbus, OPC-UA, SCADA system detection
- **Honeypot Detection**: Advanced algorithms to identify network honeypots
- **IPv6 Network Discovery**: Complete IPv6 support with link-local discovery
- **Docker Integration**: Containerized deployment with multi-architecture support

### Advanced Features to Implement
```csharp
// Example: Advanced service fingerprinting
public async Task<ServiceFingerprint> FingerprintServiceAsync(IPAddress host, int port)
{
    var banners = await CollectServiceBannersAsync(host, port);
    var certificates = await AnalyzeTlsCertificatesAsync(host, port);
    var httpHeaders = await CollectHttpHeadersAsync(host, port);
    
    return new ServiceFingerprint
    {
        ServiceName = IdentifyService(banners, certificates, httpHeaders),
        Version = ExtractVersion(banners),
        OperatingSystem = DetectOs(banners, httpHeaders),
        SecurityFeatures = AnalyzeSecurityFeatures(certificates, httpHeaders),
        VulnerabilityRisk = AssessVulnerabilityRisk(ServiceName, Version)
    };
}
```

### Security Best Practices
- **Input Sanitization**: All network inputs must be validated against injection attacks
- **Rate Limiting**: Implement adaptive rate limiting to prevent DoS on target networks
- **Privilege Escalation**: Request minimal required privileges, escalate only when needed
- **Audit Logging**: Comprehensive logging for compliance and forensic analysis
- **Encryption**: All stored data and network communications should use strong encryption

### Modern C# Features to Utilize
```csharp
// Use records for immutable data models
public record NetworkDevice(
    IPAddress IpAddress,
    string Hostname,
    ImmutableList<OpenPort> OpenPorts,
    SecurityAssessment SecurityStatus
) : IComparable<NetworkDevice>;

// Use pattern matching for service detection
public string ClassifyService(int port, string banner) => (port, banner) switch
{
    (22, var b) when b.Contains("OpenSSH") => "SSH",
    (80, var b) when b.Contains("nginx") => "HTTP (nginx)",
    (443, var b) when b.Contains("Apache") => "HTTPS (Apache)",
    (3389, _) => "RDP",
    _ => "Unknown"
};

// Use nullable reference types consistently
public async Task<ScanResult?> ScanHostAsync(string? hostname, CancellationToken cancellationToken)
{
    if (string.IsNullOrWhiteSpace(hostname))
        return null;
        
    // Implementation with proper null handling
}
```

### Docker and Containerization Guidelines
```dockerfile
# Multi-stage build for optimization
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Discovery/Discovery.csproj", "Discovery/"]
RUN dotnet restore "Discovery/Discovery.csproj"
COPY . .
WORKDIR "/src/Discovery"
RUN dotnet build "Discovery.csproj" -c Release -o /app/build

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/build .
ENTRYPOINT ["dotnet", "AdvNetDiscovery.dll"]
```

### Observability and Monitoring
```csharp
// Implement structured logging with correlation IDs
public class NetworkScanService
{
    private readonly ILogger<NetworkScanService> _logger;
    
    public async Task<ScanResults> ScanNetworkAsync(string cidr, CancellationToken cancellationToken)
    {
        var correlationId = Guid.NewGuid();
        using var scope = _logger.BeginScope(new Dictionary<string, object>
        {
            ["CorrelationId"] = correlationId,
            ["NetworkRange"] = cidr,
            ["ScanType"] = "NetworkDiscovery"
        });
        
        _logger.LogInformation("Starting network scan for {NetworkRange}", cidr);
        
        // Implement comprehensive metrics collection
        using var activity = NetworkScanActivity.StartActivity("NetworkScan");
        activity?.SetTag("network.range", cidr);
        
        try
        {
            var results = await PerformScanAsync(cidr, cancellationToken);
            _logger.LogInformation("Network scan completed. Found {HostCount} hosts", results.HostCount);
            return results;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Network scan failed for {NetworkRange}", cidr);
            throw;
        }
    }
}
```

### API Design for Future Extensions
```csharp
// Design extensible interfaces for future API integrations
public interface INetworkDiscoveryApi
{
    Task<ApiResponse<ScanResults>> ScanNetworkAsync(ScanRequest request, CancellationToken cancellationToken);
    Task<ApiResponse<VulnerabilityReport>> AssessSecurityAsync(SecurityAssessmentRequest request, CancellationToken cancellationToken);
    IAsyncEnumerable<ScanUpdate> StreamScanUpdatesAsync(string scanId, CancellationToken cancellationToken);
}

// RESTful API models
public record ScanRequest(
    string NetworkRange,
    ScanOptions Options,
    Dictionary<string, object>? Metadata = null
);

public record ApiResponse<T>(
    T Data,
    bool Success,
    string? ErrorMessage = null,
    Dictionary<string, object>? Metadata = null
);
```

### Testing Enhancement Guidelines
```csharp
// Use test fixtures for complex integration tests
[TestFixture]
public class NetworkScannerIntegrationTests
{
    private TestNetworkEnvironment _testNetwork;
    private NetworkScanner _scanner;
    
    [OneTimeSetUp]
    public async Task SetupTestEnvironment()
    {
        _testNetwork = await TestNetworkEnvironment.CreateAsync();
        _scanner = new NetworkScanner(new TestConfiguration());
    }
    
    [Test]
    [Category("Integration")]
    [Category("Performance")]
    public async Task ScanNetwork_LargeSubnet_CompletesWithinTimeout()
    {
        // Arrange
        var networkRange = "192.168.100.0/24";
        var timeout = TimeSpan.FromMinutes(2);
        
        // Act
        var stopwatch = Stopwatch.StartNew();
        var results = await _scanner.ScanNetworkAsync(networkRange, CancellationToken.None);
        stopwatch.Stop();
        
        // Assert
        Assert.That(stopwatch.Elapsed, Is.LessThan(timeout));
        Assert.That(results.Count, Is.GreaterThan(0));
    }
}
```

### Documentation Standards
- **API Documentation**: Use OpenAPI/Swagger for any REST endpoints
- **Code Comments**: Focus on "why" not "what" - explain business logic and security considerations
- **Architecture Decisions**: Document major architectural decisions with ADRs (Architecture Decision Records)
- **Security Documentation**: Document threat models and security assumptions
- **Performance Benchmarks**: Document and track performance metrics over time

### Deployment and DevOps
```yaml
# Example GitHub Actions workflow
name: CI/CD Pipeline
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Setup .NET
      uses: actions/setup-dotnet@v3
      with:
        dotnet-version: 8.0.x
    - name: Restore dependencies
      run: dotnet restore
    - name: Build
      run: dotnet build --no-restore --configuration Release
    - name: Test
      run: dotnet test --no-build --verbosity normal --collect:"XPlat Code Coverage"
    - name: Security Scan
      run: dotnet tool install --global security-scan && security-scan .
```

### Future-Proofing Considerations
- **Cloud-Native Design**: Prepare for Kubernetes deployment with health checks and graceful shutdown
- **Microservices Architecture**: Design components for potential decomposition into microservices
- **Event-Driven Architecture**: Implement domain events for loose coupling
- **Configuration Management**: Use modern configuration patterns with validation
- **Telemetry**: Implement OpenTelemetry for distributed tracing and metrics

### Ethical Hacking and Compliance
- **Legal Compliance**: Ensure all scanning activities comply with local and international laws
- **Responsible Disclosure**: Implement responsible disclosure processes for discovered vulnerabilities
- **Data Privacy**: Handle all discovered data according to GDPR, CCPA, and other privacy regulations
- **Audit Trails**: Maintain comprehensive audit logs for compliance requirements
- **User Consent**: Always ensure proper authorization before scanning any network infrastructure

## 🚀 Release Management and Versioning

### Dynamic Versioning System
The project uses a sophisticated dynamic versioning system with two primary configuration files:

**Primary Version Configuration: `Discovery/version.json`**
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
    "Enhanced IPv6 support with neighbor discovery"
  ],
  "LastUpdated": "2025-01-27T12:00:00.0000000Z",
  "LastCommitHash": "a9c443e",
  "BuildNumber": 1,
  "ReleaseDate": "2025-01-27"
}
```

**MSBuild Configuration: `Directory.Build.props`**
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

### Release Scripts and Tools

**Dynamic Release Preparation: `scripts/release.sh`**
- Automatically detects current project version from configuration files
- Cross-platform JSON parsing (with or without `jq`)
- Comprehensive build validation and testing
- Dynamic feature listing and test discovery
- Git integration for commit and branch information

**Version Management: `scripts/version-manager.sh`**
```bash
# Show current version
./scripts/version-manager.sh show

# Semantic version bumping
./scripts/version-manager.sh bump major    # 2.1.0 -> 3.0.0
./scripts/version-manager.sh bump minor    # 2.1.0 -> 2.2.0
./scripts/version-manager.sh bump patch    # 2.1.0 -> 2.1.1

# Set specific versions
./scripts/version-manager.sh set 3.0.0
./scripts/version-manager.sh set 3.0.0-alpha

# Git tag management
./scripts/version-manager.sh tag

# Run release preparation
./scripts/version-manager.sh release
```

### Version Management Best Practices

**Semantic Versioning Guidelines:**
- **Major Version (X.0.0)**: Breaking changes, major new features, architectural changes
- **Minor Version (X.Y.0)**: New features, backward-compatible enhancements
- **Patch Version (X.Y.Z)**: Bug fixes, security patches, minor improvements
- **Pre-release (X.Y.Z-alpha/beta/rc)**: Development versions, testing releases

**Release Workflow:**
```bash
# 1. Development and testing
git add .
git commit -m "feat: implement new scanning feature"

# 2. Version management
./scripts/version-manager.sh bump minor

# 3. Release preparation
./scripts/release.sh

# 4. Git tagging and publishing
./scripts/version-manager.sh tag
git push origin v2.2.0
```

**File Synchronization:**
- Both `version.json` and `Directory.Build.props` are automatically synchronized
- Build numbers are automatically incremented
- Git commit hashes and timestamps are tracked
- All MSBuild properties are updated consistently

### Continuous Integration Guidelines

**Build Validation:**
```bash
# Build validation in release script
dotnet build --configuration Release --verbosity quiet

# Test execution
dotnet test --configuration Release --no-build

# Security scanning
dotnet list package --vulnerable
```

**Release Checklist:**
- [ ] All tests passing (375+ tests)
- [ ] Build successful without errors
- [ ] Version files synchronized
- [ ] Feature list updated in version.json
- [ ] Documentation updated (README.md, HELP.md)
- [ ] Security vulnerabilities addressed
- [ ] Cross-platform compatibility verified
- [ ] Docker images built and tested

### Version File Management

**When to Update version.json:**
- Add new features to the Features array
- Update product description for major releases
- Modify copyright information annually
- Add release notes or changelog references

**When to Update Directory.Build.props:**
- Change company or author information
- Update assembly-level properties
- Modify compilation flags or constants
- Adjust NuGet package metadata

**Automated Updates:**
- Build numbers increment automatically
- Git commit hashes are tracked
- Timestamps use UTC format
- Tags follow semantic versioning (vX.Y.Z)

This tool is designed to empower security professionals with enterprise-grade capabilities while maintaining the highest standards of ethical conduct and legal compliance.