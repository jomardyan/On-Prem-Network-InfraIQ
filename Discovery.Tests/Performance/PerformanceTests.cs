namespace Discovery.Tests.Performance;

/// <summary>
/// Performance tests to ensure the application meets performance requirements
/// </summary>
public class PerformanceTests
{
    [Fact]
    public async Task SinglePortScan_ShouldCompleteWithinTimeout()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("127.0.0.1");
        var port = 80;
        var timeout = 1000;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        await NetworkScanner.ScanPortAsync(ipAddress, port, timeout);
        stopwatch.Stop();

        // Assert
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(timeout + 500); // Allow 500ms margin
    }

    [Fact]
    public async Task MultiplePingShouldCompleteInReasonableTime()
    {
        // Arrange
        var targets = new[]
        {
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("127.0.0.1")
        };
        var timeout = 1000;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var tasks = targets.Select(ip => NetworkScanner.PingHostAsync(ip, timeout));
        await Task.WhenAll(tasks);
        stopwatch.Stop();

        // Assert
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(timeout * 2); // Should be faster than sequential
    }

    [Fact]
    public void CidrParsing_ShouldBeEfficient()
    {
        // Arrange
        var cidrNotations = new[]
        {
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/16",
            "192.168.0.0/16",
            "10.10.10.0/24"
        };
        
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        for (int i = 0; i < 1000; i++)
        {
            foreach (var cidr in cidrNotations)
            {
                NetworkUtilities.TryParseCidr(cidr, out _, out _);
            }
        }
        
        stopwatch.Stop();

        // Assert
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(1000); // Should complete in under 1 second
    }

    [Fact]
    public void PortParsing_ShouldHandleLargePortLists()
    {
        // Arrange
        var largePortList = string.Join(",", Enumerable.Range(1, 1000));
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var result = NetworkUtilities.ParseCustomPorts(largePortList);
        stopwatch.Stop();

        // Assert
        result.Should().HaveCount(1000);
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(200); // Should be fast (increased for CI environments)
    }

    [Fact]
    public void OSGuessing_ShouldBeInstantaneous()
    {
        // Arrange
        var ttlValues = Enumerable.Range(1, 255).ToArray();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        for (int i = 0; i < 10000; i++)
        {
            foreach (var ttl in ttlValues)
            {
                NetworkUtilities.GuessOperatingSystem(ttl);
            }
        }
        
        stopwatch.Stop();

        // Assert
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(500); // Should be fast (increased for CI environments)
    }
}
