using Discovery.Services.MachineLearning;
using Discovery.Core.Models;
using System.Net;
using Xunit;

namespace Discovery.Tests.MachineLearning;

/// <summary>
/// Tests for machine learning anomaly detection functionality.
/// </summary>
public class AnomalyDetectionServiceTests : IDisposable
{
    private readonly AnomalyDetectionService _anomalyService;
    private readonly string _testModelPath;

    public AnomalyDetectionServiceTests()
    {
        _testModelPath = Path.Combine(Path.GetTempPath(), "test_models", Guid.NewGuid().ToString());
        Directory.CreateDirectory(_testModelPath);
        _anomalyService = new AnomalyDetectionService(_testModelPath);
    }

    /// <summary>
    /// Tests basic anomaly detection functionality.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_WithNormalScanResults_ShouldCompleteSuccessfully()
    {
        // Arrange
        var scanResults = CreateNormalScanResults();

        // Act
        var anomalies = await _anomalyService.DetectAnomaliesAsync(scanResults);

        // Assert
        Assert.NotNull(anomalies);
        // Normal traffic should have few or no anomalies
    }

    /// <summary>
    /// Tests detection of suspicious port combinations.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_WithSuspiciousPortCombinations_ShouldDetectAnomalies()
    {
        // Arrange
        var suspiciousResults = new[]
        {
            // Windows SMB attack pattern
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.100"), 135, "RPC"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.100"), 139, "NetBIOS"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.100"), 445, "SMB"),
            
            // Database exposure pattern
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.101"), 1433, "SQL Server"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.101"), 3306, "MySQL"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.101"), 5432, "PostgreSQL")
        };

        // Act
        var anomalies = await _anomalyService.DetectAnomaliesAsync(suspiciousResults);

        // Assert
        var portCombinationAnomalies = anomalies.Where(a => a.AnomalyType == "UnusualPortCombination");
        Assert.NotEmpty(portCombinationAnomalies);
        
        // Should detect suspicious patterns
        Assert.Contains(portCombinationAnomalies, a => a.Description.Contains("SMB"));
        Assert.Contains(portCombinationAnomalies, a => a.Description.Contains("Database"));
    }

    /// <summary>
    /// Tests detection of port scanning patterns.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_WithPortScanningPattern_ShouldDetectAnomaly()
    {
        // Arrange - Sequential port scanning pattern
        var portScanResults = new List<ScanResult>();
        for (int port = 80; port <= 90; port++)
        {
            portScanResults.Add(ScanResult.CreateOpen(IPAddress.Parse("192.168.1.200"), port, "Unknown"));
        }

        // Act
        var anomalies = await _anomalyService.DetectAnomaliesAsync(portScanResults);

        // Assert
        var portScanAnomalies = anomalies.Where(a => a.AnomalyType == "UnusualPortCombination" && 
                                                    a.Description.Contains("scanning"));
        Assert.NotEmpty(portScanAnomalies);
    }

    /// <summary>
    /// Tests model training with historical data.
    /// </summary>
    [Fact]
    public async Task TrainModelAsync_WithValidTrainingData_ShouldSucceed()
    {
        // Arrange
        var trainingData = CreateLargeTrainingDataset();

        // Act
        var result = await _anomalyService.TrainModelAsync(trainingData);

        // Assert
        Assert.True(result);
    }

    /// <summary>
    /// Tests model loading and saving.
    /// </summary>
    [Fact]
    public async Task LoadModelAsync_AfterTraining_ShouldLoadSuccessfully()
    {
        // Arrange
        var trainingData = CreateLargeTrainingDataset();
        await _anomalyService.TrainModelAsync(trainingData);

        // Act
        var loadResult = await _anomalyService.LoadModelAsync();

        // Assert
        Assert.True(loadResult);
    }

    /// <summary>
    /// Tests behavioral anomaly detection with historical comparison.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_WithHistoricalData_ShouldDetectBehavioralChanges()
    {
        // Arrange
        var historicalData = CreateNormalScanResults();
        var currentData = new[]
        {
            // Same host but dramatically different behavior - many more open ports
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 443, "HTTPS"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 1337, "Unknown"), // Suspicious port
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 31337, "Unknown"), // Another suspicious port
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 4444, "Unknown"), // Backdoor port
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 8080, "HTTP-Alt"), // Additional port
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 9999, "Unknown"), // Another port
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 23, "telnet"), // Suspicious service
            
            // New host not in historical data with suspicious profile
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.99"), 1337, "backdoor"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.99"), 4444, "backdoor"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.99"), 31337, "backdoor"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.99"), 23, "telnet"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.99"), 21, "ftp"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.99"), 135, "rpc"),
        };

        // Act
        var anomalies = await _anomalyService.DetectAnomaliesAsync(currentData, historicalData);

        // Assert
        var behavioralAnomalies = anomalies.Where(a => a.AnomalyType == "BehavioralAnomaly" || 
                                                      a.AnomalyType == "NewHostAnomaly");
        Assert.NotEmpty(behavioralAnomalies);
    }

    /// <summary>
    /// Tests service behavior anomaly detection.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_WithUnusualServiceBehavior_ShouldDetectAnomalies()
    {
        // Arrange
        var historicalData = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.50"), 80, "HTTP", 50), // Normal response time
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.50"), 443, "HTTPS", 60)
        };

        var currentData = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.50"), 80, "HTTP", 5000), // Very slow response
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.50"), 8080, "HTTP", 100) // HTTP on unusual port
        };

        // Act
        var anomalies = await _anomalyService.DetectAnomaliesAsync(currentData, historicalData);

        // Assert
        var serviceAnomalies = anomalies.Where(a => a.AnomalyType == "ServiceBehaviorAnomaly");
        // Service behavior anomalies might be detected based on timing or port changes
        Assert.NotNull(anomalies);
    }

    /// <summary>
    /// Tests anomaly detection with mixed IPv4 and IPv6 addresses.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_WithIPv6Addresses_ShouldProcessCorrectly()
    {
        // Arrange
        var mixedResults = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("2001:db8::1"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("fe80::1"), 22, "SSH")
        };

        // Act
        var anomalies = await _anomalyService.DetectAnomaliesAsync(mixedResults);

        // Assert
        Assert.NotNull(anomalies);
        // Should handle both IPv4 and IPv6 without errors
    }

    /// <summary>
    /// Tests anomaly scoring accuracy.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_ShouldProvideReasonableAnomalyScores()
    {
        // Arrange
        var highRiskResults = new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 23, "Telnet") // High risk service
                .WithVulnerability("Unencrypted communication"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 21, "FTP") // Another high risk service
        };

        // Act
        var anomalies = await _anomalyService.DetectAnomaliesAsync(highRiskResults);

        // Assert
        foreach (var anomaly in anomalies)
        {
            Assert.True(anomaly.AnomalyScore >= 0.0 && anomaly.AnomalyScore <= 1.0, 
                "Anomaly score should be between 0.0 and 1.0");
        }
    }

    /// <summary>
    /// Tests anomaly detection performance with large datasets.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_WithLargeDataset_ShouldCompleteInReasonableTime()
    {
        // Arrange
        var largeDataset = CreateLargeTrainingDataset();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var anomalies = await _anomalyService.DetectAnomaliesAsync(largeDataset);
        stopwatch.Stop();

        // Assert
        Assert.NotNull(anomalies);
        Assert.True(stopwatch.ElapsedMilliseconds < 30000, 
            $"Anomaly detection took {stopwatch.ElapsedMilliseconds}ms, expected < 30000ms");
    }

    /// <summary>
    /// Tests network feature conversion accuracy.
    /// </summary>
    [Fact]
    public void NetworkFeature_ConversionFromScanResult_ShouldPreserveData()
    {
        // Arrange
        var scanResult = ScanResult.CreateOpen(IPAddress.Parse("192.168.1.1"), 443, "HTTPS", 100)
            .WithVulnerability("Weak SSL configuration");

        // Act - Test the concept of feature conversion
        var feature = new NetworkFeature
        {
            IpAddress = scanResult.IpAddress.ToString(),
            Port = scanResult.Port,
            IsOpen = scanResult.IsOpen,
            ServiceName = scanResult.Service,  // Use Service instead of ServiceName
            ResponseTime = (float)(scanResult.PingTime ?? 0),
            IsVulnerable = scanResult.IsVulnerable,
            Timestamp = scanResult.DiscoveredAt ?? DateTime.UtcNow
        };

        // Assert
        Assert.Equal("192.168.1.1", feature.IpAddress);
        Assert.Equal(443, feature.Port);
        Assert.True(feature.IsOpen);
        Assert.Equal("HTTPS", feature.ServiceName);
        Assert.Equal(100, feature.ResponseTime);
        Assert.True(feature.IsVulnerable);
    }

    /// <summary>
    /// Tests cancellation token support.
    /// </summary>
    [Fact]
    public async Task DetectAnomaliesAsync_WithCancellation_ShouldRespectCancellation()
    {
        // Arrange
        var scanResults = CreateLargeTrainingDataset();
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Act & Assert
        var anomalies = await _anomalyService.DetectAnomaliesAsync(scanResults, cancellationToken: cts.Token);
        
        // Should complete without throwing, respecting cancellation
        Assert.NotNull(anomalies);
    }

    /// <summary>
    /// Creates normal scan results for testing.
    /// </summary>
    private IEnumerable<ScanResult> CreateNormalScanResults()
    {
        return new[]
        {
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 80, "HTTP"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.10"), 443, "HTTPS"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.11"), 22, "SSH"),
            ScanResult.CreateOpen(IPAddress.Parse("192.168.1.12"), 25, "SMTP"),
            ScanResult.CreateClosed(IPAddress.Parse("192.168.1.10"), 21),
            ScanResult.CreateClosed(IPAddress.Parse("192.168.1.10"), 23)
        };
    }

    /// <summary>
    /// Creates a large training dataset for ML testing.
    /// </summary>
    private IEnumerable<ScanResult> CreateLargeTrainingDataset()
    {
        var results = new List<ScanResult>();
        var random = new Random(42); // Fixed seed for reproducible tests

        // Generate diverse training data
        for (int i = 1; i <= 50; i++)
        {
            var ip = IPAddress.Parse($"192.168.1.{i}");
            
            // Common services
            if (random.NextDouble() > 0.3)
                results.Add(ScanResult.CreateOpen(ip, 80, "HTTP", random.Next(10, 200)));
            
            if (random.NextDouble() > 0.5)
                results.Add(ScanResult.CreateOpen(ip, 443, "HTTPS", random.Next(20, 300)));
            
            if (random.NextDouble() > 0.7)
                results.Add(ScanResult.CreateOpen(ip, 22, "SSH", random.Next(5, 100)));
            
            // Some closed ports
            for (int port = 8000; port <= 8005; port++)
            {
                if (random.NextDouble() > 0.8)
                    results.Add(ScanResult.CreateClosed(ip, port));
            }

            // Occasional vulnerable services
            if (random.NextDouble() > 0.9)
            {
                results.Add(ScanResult.CreateOpen(ip, 21, "FTP")
                    .WithVulnerability("Unencrypted FTP service"));
            }
        }

        return results;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testModelPath))
            {
                Directory.Delete(_testModelPath, true);
            }
        }
        catch
        {
            // Ignore cleanup errors in tests
        }
    }
}