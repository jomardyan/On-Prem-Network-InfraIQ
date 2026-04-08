namespace Discovery.Tests.Security;

/// <summary>
/// Security-focused tests to ensure the application handles edge cases safely
/// </summary>
public class SecurityTests
{
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("../../../../etc/passwd")]
    [InlineData("C:\\Windows\\System32\\drivers\\etc\\hosts")]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("'; DROP TABLE users; --")]
    public void ParseCustomPorts_ShouldHandleMaliciousInput(string? maliciousInput)
    {
        // Act & Assert - Should not throw exceptions
        var result = NetworkUtilities.ParseCustomPorts(maliciousInput ?? "");
        result.Should().NotBeNull();
    }

    [Theory]
    [InlineData("999999999999999999999")]
    [InlineData("-999999999999999999999")]
    [InlineData("999999999999999999999-999999999999999999999")]
    public void ParseCustomPorts_ShouldHandleExtremeNumbers(string extremeInput)
    {
        // Act & Assert - Should not throw exceptions or cause overflow
        var result = NetworkUtilities.ParseCustomPorts(extremeInput);
        result.Should().NotBeNull();
        result.Should().BeEmpty(); // Invalid numbers should be ignored
    }

    [Fact]
    public void TryParseCidr_ShouldHandleMalformedInput()
    {
        // Arrange
        var malformedInputs = new[]
        {
            null,
            "",
            "not-an-ip",
            "999.999.999.999/24",
            "192.168.1.0/999",
            "192.168.1.0/-1",
            "../../../etc/passwd",
            "\\\\server\\share",
            "<script>alert('xss')</script>"
        };

        // Act & Assert
        foreach (var input in malformedInputs)
        {
            var result = NetworkUtilities.TryParseCidr(input!, out var networkAddress, out var subnetMask);
            result.Should().BeFalse();
            networkAddress.Should().BeNull();
            subnetMask.Should().Be(0);
        }
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(65536)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public async Task ScanPortAsync_ShouldHandleInvalidPortsSecurely(int invalidPort)
    {
        // Arrange
        var ipAddress = IPAddress.Parse("127.0.0.1");

        // Act & Assert
        if (invalidPort < 1 || invalidPort > 65535)
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => NetworkScanner.ScanPortAsync(ipAddress, invalidPort, 1000));
        }
    }

    [Fact]
    public void IsValidIPAddress_ShouldRejectMaliciousInputs()
    {
        // Arrange
        var maliciousInputs = new[]
        {
            "../../../etc/passwd",
            "\\\\malicious\\server",
            "<script>alert('xss')</script>",
            "'; DROP TABLE ips; --",
            "\0\0\0\0",
            new string('A', 1000), // Very long string
            "192.168.1.1\r\n192.168.1.2", // Multi-line injection
            "192.168.1.1 && rm -rf /" // Command injection attempt
        };

        // Act & Assert
        foreach (var maliciousInput in maliciousInputs)
        {
            var result = NetworkUtilities.IsValidIPAddress(maliciousInput);
            result.Should().BeFalse();
        }
    }

    [Fact]
    public void GuessOperatingSystem_ShouldHandleExtremeValues()
    {
        // Arrange
        var extremeValues = new[] { int.MinValue, int.MaxValue, -1, 0, 999999 };

        // Act & Assert
        foreach (var value in extremeValues)
        {
            // Should not throw exceptions
            var result = NetworkUtilities.GuessOperatingSystem(value);
            result.Should().NotBeNull();
            result.Should().NotBeEmpty();
        }
    }

    [Fact]
    public async Task PingHostAsync_ShouldHandlePrivateAndPublicIPs()
    {
        // Arrange - Test various IP ranges
        var testIPs = new[]
        {
            IPAddress.Parse("127.0.0.1"),      // Loopback
            IPAddress.Parse("192.168.1.1"),   // Private Class C
            IPAddress.Parse("10.0.0.1"),      // Private Class A
            IPAddress.Parse("172.16.0.1"),    // Private Class B
            IPAddress.Parse("169.254.1.1"),   // Link-local
            IPAddress.Parse("224.0.0.1")      // Multicast
        };

        // Act & Assert
        foreach (var ip in testIPs)
        {
            // Should handle all IP types without exceptions
            var result = await NetworkScanner.PingHostAsync(ip, 1000);
            result.Should().NotBeNull();
        }
    }

    [Fact]
    public void CalculateNetworkRange_ShouldPreventIntegerOverflow()
    {
        // Arrange
        var extremeNetwork = IPAddress.Parse("255.255.255.0");
        var extremeMask = IPAddress.Parse("255.255.255.255");

        // Act & Assert - Should not cause overflow
        var result = NetworkUtilities.CalculateNetworkRange(extremeNetwork, extremeMask);
        result.Should().NotBeNull();
        result.StartRange.Should().BeGreaterOrEqualTo(0);
        result.EndRange.Should().BeLessOrEqualTo(255);
    }
}
