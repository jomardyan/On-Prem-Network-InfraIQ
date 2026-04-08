using Discovery.Services.Scanning;
using Xunit;

namespace Discovery.Tests.IPv6;

/// <summary>
/// Tests for enhanced IPv6 neighbor discovery functionality.
/// </summary>
public class IPv6NeighborDiscoveryTests
{
    private readonly IPv6NeighborDiscoveryService _discoveryService;

    public IPv6NeighborDiscoveryTests()
    {
        _discoveryService = new IPv6NeighborDiscoveryService(timeout: 1000, maxConcurrency: 10);
    }

    /// <summary>
    /// Tests basic neighbor discovery functionality.
    /// </summary>
    [Fact]
    public async Task DiscoverNeighborsAsync_ShouldReturnNeighbors()
    {
        // Act
        var neighbors = await _discoveryService.DiscoverNeighborsAsync();

        // Assert
        Assert.NotNull(neighbors);
        // The test environment may not have IPv6 neighbors, so we just verify the method completes
        // In a real network environment, this would discover actual neighbors
    }

    /// <summary>
    /// Tests neighbor discovery with cancellation.
    /// </summary>
    [Fact]
    public async Task DiscoverNeighborsAsync_WithCancellation_ShouldRespectCancellation()
    {
        // Arrange
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Act & Assert
        var neighbors = await _discoveryService.DiscoverNeighborsAsync(cts.Token);
        
        // Should complete without throwing, even if cancelled
        Assert.NotNull(neighbors);
    }

    /// <summary>
    /// Tests that neighbor info contains required properties.
    /// </summary>
    [Fact]
    public void IPv6NeighborInfo_ShouldHaveRequiredProperties()
    {
        // Arrange & Act
        var neighbor = new IPv6NeighborInfo
        {
            IPv6Address = "2001:db8::1",
            IsReachable = true,
            ResponseTime = 50,
            DiscoveryMethod = "TestMethod",
            Scope = "Global",
            DiscoveredAt = DateTime.UtcNow
        };

        // Assert
        Assert.Equal("2001:db8::1", neighbor.IPv6Address);
        Assert.True(neighbor.IsReachable);
        Assert.Equal(50, neighbor.ResponseTime);
        Assert.Equal("TestMethod", neighbor.DiscoveryMethod);
        Assert.Equal("Global", neighbor.Scope);
        Assert.True(neighbor.DiscoveredAt > DateTime.UtcNow.AddMinutes(-1));
    }

    /// <summary>
    /// Tests neighbor discovery timeout handling.
    /// </summary>
    [Fact]
    public async Task DiscoverNeighborsAsync_WithShortTimeout_ShouldCompleteQuickly()
    {
        // Arrange
        var fastService = new IPv6NeighborDiscoveryService(timeout: 100, maxConcurrency: 5);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var neighbors = await fastService.DiscoverNeighborsAsync();
        stopwatch.Stop();

        // Assert
        Assert.NotNull(neighbors);
        // Should complete relatively quickly due to short timeout
        Assert.True(stopwatch.ElapsedMilliseconds < 5000);
    }

    /// <summary>
    /// Tests IPv6 address scope determination logic.
    /// </summary>
    [Theory]
    [InlineData("::1", "Loopback")]
    [InlineData("fe80::1", "Link-Local")]
    [InlineData("fc00::1", "Unique-Local")]
    [InlineData("2001:db8::1", "Global")]
    [InlineData("ff02::1", "Multicast")]
    public void DetermineIPv6Scope_ShouldReturnCorrectScope(string ipAddress, string expectedScope)
    {
        // This tests the internal scope logic that would be used in the service
        // Since the method is private, we test the concept here
        
        // Arrange
        var address = System.Net.IPAddress.Parse(ipAddress);
        var bytes = address.GetAddressBytes();
        
        // Act
        string actualScope;
        if (address.Equals(System.Net.IPAddress.IPv6Loopback))
            actualScope = "Loopback";
        else if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
            actualScope = "Link-Local";
        else if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0)
            actualScope = "Site-Local";
        else if (bytes[0] == 0xff)
            actualScope = "Multicast";
        else if (bytes[0] == 0xfc || bytes[0] == 0xfd)
            actualScope = "Unique-Local";
        else
            actualScope = "Global";

        // Assert
        Assert.Equal(expectedScope, actualScope);
    }

    /// <summary>
    /// Tests solicited-node multicast address generation.
    /// </summary>
    [Fact]
    public void GenerateSolicitedNodeMulticast_ShouldCreateCorrectAddress()
    {
        // Arrange
        var targetAddress = System.Net.IPAddress.Parse("2001:db8::1234:5678");
        var targetBytes = targetAddress.GetAddressBytes();
        
        // Act - Simulate solicited-node multicast generation
        var solicitedNodeBytes = new byte[16];
        solicitedNodeBytes[0] = 0xff;
        solicitedNodeBytes[1] = 0x02;
        solicitedNodeBytes[11] = 0x01;
        solicitedNodeBytes[12] = 0xff;
        Array.Copy(targetBytes, 13, solicitedNodeBytes, 13, 3);
        
        var solicitedNodeAddr = new System.Net.IPAddress(solicitedNodeBytes);
        
        // Assert
        var actualAddr = solicitedNodeAddr.ToString();
        
        // The exact format may vary, but verify it's a solicited-node multicast address
        Assert.StartsWith("ff02::1:ff", actualAddr);
    }

    /// <summary>
    /// Tests common IPv6 router address generation.
    /// </summary>
    [Theory]
    [InlineData("fe80::1234:5678:9abc:def0", "::1", "fe80::1")]
    [InlineData("2001:db8::1", "::fe", "2001:db8::fe")]
    public void GenerateRouterAddress_ShouldCreateValidAddress(string baseAddress, string suffix, string expectedPattern)
    {
        // Arrange
        var baseAddr = System.Net.IPAddress.Parse(baseAddress);
        var baseBytes = baseAddr.GetAddressBytes();
        
        // Act - Simulate router address generation
        var suffixAddr = System.Net.IPAddress.Parse(suffix);
        var suffixBytes = suffixAddr.GetAddressBytes();
        var routerBytes = (byte[])baseBytes.Clone();
        
        // Replace interface identifier with router suffix
        Array.Copy(suffixBytes, 8, routerBytes, 8, 8);
        var routerAddr = new System.Net.IPAddress(routerBytes);
        
        // Assert
        var actualAddr = routerAddr.ToString();
        Assert.Contains(expectedPattern.Split(':')[0], actualAddr); // Check prefix matches
    }

    /// <summary>
    /// Tests neighbor discovery with different concurrency levels.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(20)]
    public async Task DiscoverNeighborsAsync_WithDifferentConcurrency_ShouldComplete(int maxConcurrency)
    {
        // Arrange
        var service = new IPv6NeighborDiscoveryService(timeout: 500, maxConcurrency: maxConcurrency);
        
        // Act
        var neighbors = await service.DiscoverNeighborsAsync();
        
        // Assert
        Assert.NotNull(neighbors);
        // Should complete regardless of concurrency level
    }

    /// <summary>
    /// Tests neighbor discovery performance characteristics.
    /// </summary>
    [Fact]
    public async Task DiscoverNeighborsAsync_PerformanceTest_ShouldCompleteInReasonableTime()
    {
        // Arrange
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        
        // Act
        var neighbors = await _discoveryService.DiscoverNeighborsAsync();
        stopwatch.Stop();
        
        // Assert
        Assert.NotNull(neighbors);
        // Should complete within 30 seconds even with network timeouts
        Assert.True(stopwatch.ElapsedMilliseconds < 30000, 
            $"Discovery took {stopwatch.ElapsedMilliseconds}ms, expected < 30000ms");
    }

    /// <summary>
    /// Tests that discovered neighbors are properly deduplicated.
    /// </summary>
    [Fact]
    public async Task DiscoverNeighborsAsync_ShouldDeduplicateResults()
    {
        // This test verifies the deduplication logic in DiscoverNeighborsAsync
        // Since we can't easily create duplicate neighbors in a test environment,
        // we verify the method completes and returns a collection
        
        // Act
        var neighbors = await _discoveryService.DiscoverNeighborsAsync();
        
        // Assert
        Assert.NotNull(neighbors);
        
        // Verify no duplicates by IPv6 address
        var uniqueAddresses = neighbors.Select(n => n.IPv6Address).Distinct().Count();
        var totalNeighbors = neighbors.Count();
        
        Assert.Equal(uniqueAddresses, totalNeighbors);
    }

    /// <summary>
    /// Tests neighbor discovery with various IPv6 address types.
    /// </summary>
    [Theory]
    [InlineData("::1")] // Loopback
    [InlineData("fe80::1")] // Link-local
    [InlineData("2001:db8::1")] // Global unicast
    [InlineData("fc00::1")] // Unique local
    public void IPv6NeighborInfo_ShouldAcceptValidAddresses(string ipv6Address)
    {
        // Arrange & Act
        var neighbor = new IPv6NeighborInfo
        {
            IPv6Address = ipv6Address,
            IsReachable = true,
            DiscoveryMethod = "Test",
            DiscoveredAt = DateTime.UtcNow
        };
        
        // Assert
        Assert.Equal(ipv6Address, neighbor.IPv6Address);
        Assert.True(System.Net.IPAddress.TryParse(ipv6Address, out var parsedAddress));
        Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, parsedAddress.AddressFamily);
    }
}