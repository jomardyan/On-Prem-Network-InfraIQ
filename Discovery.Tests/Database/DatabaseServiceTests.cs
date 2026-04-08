using Discovery.Core.Data;
using Discovery.Core.Models;
using Discovery.Core.Interfaces;
using Discovery.Services.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Net;
using Xunit;

namespace Discovery.Tests.Database;

/// <summary>
/// Tests for database functionality.
/// </summary>
public class DatabaseServiceTests : IDisposable
{
    private readonly NetworkDiscoveryDbContext _context;
    private readonly DatabaseService _databaseService;

    public DatabaseServiceTests()
    {
        var options = new DbContextOptionsBuilder<NetworkDiscoveryDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;

        _context = new NetworkDiscoveryDbContext(options);
        _databaseService = new DatabaseService(_context);
    }

    /// <summary>
    /// Tests database initialization.
    /// </summary>
    [Fact]
    public async Task InitializeDatabaseAsync_ShouldCreateDatabase()
    {
        // Act
        var result = await _databaseService.InitializeDatabaseAsync();

        // Assert
        Assert.True(result);
        Assert.True(await _context.Database.CanConnectAsync());
    }

    /// <summary>
    /// Tests creating a scan session with results.
    /// </summary>
    [Fact]
    public async Task CreateCompleteScanSessionAsync_ShouldCreateSessionWithResults()
    {
        // Arrange
        var scanResults = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 443, "HTTPS"),
            ScanResult.CreateClosed(IPAddress.Parse("192.168.1.1"), 22)
        };

        // Act
        var session = await _databaseService.CreateCompleteScanSessionAsync(
            "Test Scan",
            "NetworkScan",
            "192.168.1.0/24",
            scanResults);

        // Assert
        Assert.NotEqual(Guid.Empty, session.Id);
        Assert.Equal("Test Scan", session.Name);
        Assert.Equal("NetworkScan", session.ScanType);
        Assert.Equal("192.168.1.0/24", session.Target);

        // Verify results were stored
        var storedResults = await _databaseService.Results.GetResultsAsync(session.Id);
        Assert.Equal(3, storedResults.Count());

        var openPorts = await _databaseService.Results.GetOpenPortsAsync(session.Id);
        Assert.Equal(2, openPorts.Count());
    }

    /// <summary>
    /// Tests creating a session with vulnerabilities.
    /// </summary>
    [Fact]
    public async Task CreateCompleteScanSessionAsync_WithVulnerabilities_ShouldStoreVulnerabilities()
    {
        // Arrange
        var scanResults = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 23, "Telnet")
                .WithVulnerability("Telnet allows unencrypted communication")
        };

        var vulnerabilities = new[]
        {
            new VulnerabilityResultEntity
            {
                IpAddress = "192.168.1.1",
                Port = 23,
                Title = "Unencrypted Telnet Service",
                Description = "Telnet service allows unencrypted communication",
                Severity = VulnerabilitySeverity.High,
                RecommendedFix = "Disable Telnet and use SSH instead"
            }
        };

        // Act
        var session = await _databaseService.CreateCompleteScanSessionAsync(
            "Vulnerability Scan",
            "VulnerabilityScan",
            "192.168.1.1",
            scanResults,
            vulnerabilities);

        // Assert
        var storedVulns = await _databaseService.Vulnerabilities.GetVulnerabilitiesAsync(session.Id);
        Assert.Single(storedVulns);

        var vuln = storedVulns.First();
        Assert.Equal("192.168.1.1", vuln.IpAddress);
        Assert.Equal(23, vuln.Port);
        Assert.Equal(VulnerabilitySeverity.High, vuln.Severity);
    }

    /// <summary>
    /// Tests getting database statistics.
    /// </summary>
    [Fact]
    public async Task GetStatisticsAsync_ShouldReturnCorrectStatistics()
    {
        // Arrange
        var scanResults = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.2"), 22, "SSH")
                .WithVulnerability("Weak SSH configuration")
        };

        await _databaseService.CreateCompleteScanSessionAsync(
            "Test Scan 1",
            "NetworkScan",
            "192.168.1.0/24",
            scanResults);

        await _databaseService.CreateCompleteScanSessionAsync(
            "Test Scan 2",
            "PortScan",
            "10.0.0.1",
            new[] { ScanResult.CreateOpen(IPAddress.Parse("10.0.0.1"), 443, "HTTPS") });

        // Act
        var statistics = await _databaseService.GetStatisticsAsync();

        // Assert
        Assert.Equal(2, statistics.TotalScanSessions);
        Assert.Equal(3, statistics.TotalScanResults);
        Assert.NotNull(statistics.LastScanDate);
        Assert.True(statistics.LastScanDate > DateTime.UtcNow.AddMinutes(-5));
    }

    /// <summary>
    /// Tests session search functionality.
    /// </summary>
    [Fact]
    public async Task SearchResults_ShouldFindMatchingResults()
    {
        // Arrange
        var scanResults = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 443, "HTTPS"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.2"), 22, "SSH"),
            ScanResult.CreateClosed(IPAddress.Parse("192.168.1.3"), 80)
        };

        var session = await _databaseService.CreateCompleteScanSessionAsync(
            "Search Test",
            "NetworkScan",
            "192.168.1.0/24",
            scanResults);

        // Act - Search for specific IP
        var searchCriteria = new ScanResultSearchCriteria
        {
            SessionId = session.Id,
            IpAddress = "192.168.1.1"
        };

        var results = await _databaseService.Results.SearchResultsAsync(searchCriteria);

        // Assert
        Assert.Equal(2, results.Count());
        Assert.All(results, r => Assert.Equal("192.168.1.1", r.IpAddress.ToString()));

        // Act - Search for open ports only
        var openPortsCriteria = new ScanResultSearchCriteria
        {
            SessionId = session.Id,
            OpenPortsOnly = true
        };

        var openResults = await _databaseService.Results.SearchResultsAsync(openPortsCriteria);

        // Assert
        Assert.Equal(3, openResults.Count());
        Assert.All(openResults, r => Assert.True(r.IsOpen));
    }

    /// <summary>
    /// Tests IPv6 scan result storage.
    /// </summary>
    [Fact]
    public async Task CreateSession_WithIPv6Results_ShouldStoreCorrectly()
    {
        // Arrange
        var ipv6Results = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("2001:db8::1"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("fe80::1"), 22, "SSH")
        };

        // Act
        var session = await _databaseService.CreateCompleteScanSessionAsync(
            "IPv6 Test",
            "IPv6Scan",
            "2001:db8::/64",
            ipv6Results);

        // Assert
        var ipv6StoredResults = await _databaseService.Results.GetIPv6ResultsAsync(session.Id);
        Assert.Equal(2, ipv6StoredResults.Count());

        foreach (var result in ipv6StoredResults)
        {
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, result.IpAddress.AddressFamily);
        }
    }

    /// <summary>
    /// Tests data export functionality.
    /// </summary>
    [Fact]
    public async Task ExportSessionToJsonAsync_ShouldReturnValidJson()
    {
        // Arrange
        var scanResults = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 443, "HTTPS")
        };

        var vulnerabilities = new[]
        {
            new VulnerabilityResultEntity
            {
                IpAddress = "192.168.1.1",
                Port = 80,
                Title = "HTTP Service",
                Description = "Unencrypted HTTP service detected",
                Severity = VulnerabilitySeverity.Medium,
                RecommendedFix = "Use HTTPS instead"
            }
        };

        var session = await _databaseService.CreateCompleteScanSessionAsync(
            "Export Test",
            "NetworkScan",
            "192.168.1.1",
            scanResults,
            vulnerabilities);

        // Act
        var json = await _databaseService.ExportSessionToJsonAsync(session.Id);

        // Assert
        Assert.NotNull(json);
        Assert.Contains("Export Test", json);
        Assert.Contains("192.168.1.1", json);
        Assert.Contains("HTTP Service", json);

        // Verify it's valid JSON
        var jsonDocument = System.Text.Json.JsonDocument.Parse(json);
        Assert.NotNull(jsonDocument);
        jsonDocument.Dispose();
    }

    /// <summary>
    /// Tests data cleanup functionality.
    /// </summary>
    [Fact]
    public async Task CleanupOldDataAsync_ShouldRemoveOldSessions()
    {
        // Arrange
        var oldSession = new ScanSession
        {
            Name = "Old Session",
            ScanType = "NetworkScan",
            Target = "192.168.1.0/24",
            StartedAt = DateTime.UtcNow.AddDays(-100),
            CompletedAt = DateTime.UtcNow.AddDays(-100)
        };

        var recentSession = new ScanSession
        {
            Name = "Recent Session",
            ScanType = "NetworkScan",
            Target = "10.0.0.0/24",
            StartedAt = DateTime.UtcNow.AddDays(-10),
            CompletedAt = DateTime.UtcNow.AddDays(-10)
        };

        await _databaseService.Sessions.CreateSessionAsync(oldSession);
        await _databaseService.Sessions.CreateSessionAsync(recentSession);

        // Act
        var deletedCount = await _databaseService.CleanupOldDataAsync(retentionDays: 30);

        // Assert
        Assert.Equal(1, deletedCount);

        var remainingSessions = await _databaseService.Sessions.GetSessionsAsync();
        Assert.Single(remainingSessions);
        Assert.Equal("Recent Session", remainingSessions.First().Name);
    }

    public void Dispose()
    {
        _context?.Dispose();
    }
}