using System.Net;
using System.Threading.Tasks;
using Discovery.Core;
using Discovery.Core.Configuration;
using Discovery.Tools;
using Xunit;

namespace Discovery.Tests.Tools
{
    public class StealthScannerTests
    {
        [Fact]
        public void StealthConfig_Default_ShouldHaveCorrectValues()
        {
            // Arrange & Act
            var config = StealthConfig.Default;

            // Assert
            Assert.Equal(50, config.MinScanDelay);
            Assert.Equal(200, config.MaxScanDelay);
            Assert.False(config.RandomizeSourcePorts);
            Assert.False(config.UsePacketFragmentation);
            Assert.False(config.RotateUserAgents);
            Assert.Equal(100, config.MaxConcurrentConnections);
            Assert.False(config.RandomizeScanPattern);
            Assert.Equal(2000, config.ConnectionTimeout);
        }

        [Fact]
        public void StealthConfig_HighStealth_ShouldHaveCorrectValues()
        {
            // Arrange & Act
            var config = StealthConfig.HighStealth;

            // Assert
            Assert.Equal(500, config.MinScanDelay);
            Assert.Equal(2000, config.MaxScanDelay);
            Assert.True(config.RandomizeSourcePorts);
            Assert.True(config.UsePacketFragmentation);
            Assert.True(config.RotateUserAgents);
            Assert.Equal(5, config.MaxConcurrentConnections);
            Assert.True(config.RandomizeScanPattern);
            Assert.Equal(5000, config.ConnectionTimeout);
        }

        [Fact]
        public void StealthConfig_GetRandomDelay_ShouldReturnValueWithinRange()
        {
            // Arrange
            var config = new StealthConfig { MinScanDelay = 100, MaxScanDelay = 500 };

            // Act & Assert
            for (int i = 0; i < 10; i++)
            {
                var delay = config.GetRandomDelay();
                Assert.True(delay >= 100 && delay <= 500, $"Delay {delay} is not within range 100-500");
            }
        }

        [Fact]
        public void StealthConfig_GetRandomSourcePort_WithRandomizationDisabled_ShouldReturnZero()
        {
            // Arrange
            var config = new StealthConfig { RandomizeSourcePorts = false };

            // Act
            var port = config.GetRandomSourcePort();

            // Assert
            Assert.Equal(0, port);
        }

        [Fact]
        public void StealthConfig_GetRandomSourcePort_WithRandomizationEnabled_ShouldReturnHighPort()
        {
            // Arrange
            var config = new StealthConfig { RandomizeSourcePorts = true };

            // Act & Assert
            for (int i = 0; i < 10; i++)
            {
                var port = config.GetRandomSourcePort();
                Assert.True(port >= 32768 && port <= 65535, $"Port {port} is not in high port range");
            }
        }

        [Fact]
        public void StealthConfig_GetRandomUserAgent_WithRotationDisabled_ShouldReturnDefault()
        {
            // Arrange
            var config = new StealthConfig { RotateUserAgents = false };
            var expectedDefault = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

            // Act
            var userAgent = config.GetRandomUserAgent();

            // Assert
            Assert.Equal(expectedDefault, userAgent);
        }

        [Fact]
        public void StealthConfig_GetRandomUserAgent_WithRotationEnabled_ShouldReturnVariedAgents()
        {
            // Arrange
            var config = new StealthConfig { RotateUserAgents = true };
            var userAgents = new HashSet<string>();

            // Act
            for (int i = 0; i < 20; i++)
            {
                userAgents.Add(config.GetRandomUserAgent());
            }

            // Assert
            Assert.True(userAgents.Count > 1, "Should return different user agents when rotation is enabled");
        }

        [Fact]
        public void StealthScanner_RandomizePortOrder_WithRandomizationDisabled_ShouldReturnSameOrder()
        {
            // Arrange
            var ports = new[] { 80, 443, 22, 21, 25 };

            // Act
            var result = StealthScanner.RandomizePortOrder(ports, false);

            // Assert
            Assert.Equal(ports, result.ToArray());
        }

        [Fact]
        public void StealthScanner_RandomizePortOrder_WithRandomizationEnabled_ShouldContainAllPorts()
        {
            // Arrange
            var ports = new[] { 80, 443, 22, 21, 25, 53, 110, 143, 993, 995 };

            // Act
            var result = StealthScanner.RandomizePortOrder(ports, true).ToArray();

            // Assert
            Assert.Equal(ports.Length, result.Length);
            
            // Check that all original ports are present
            foreach (var port in ports)
            {
                Assert.Contains(port, result);
            }
        }

        [Fact]
        public void StealthScanner_RandomizeIpOrder_WithRandomizationDisabled_ShouldReturnSameOrder()
        {
            // Arrange
            var ips = new[]
            {
                IPAddress.Parse("192.168.1.1"),
                IPAddress.Parse("192.168.1.2"),
                IPAddress.Parse("192.168.1.3")
            };

            // Act
            var result = StealthScanner.RandomizeIpOrder(ips, false);

            // Assert
            Assert.Equal(ips, result.ToArray());
        }

        [Fact]
        public void StealthScanner_RandomizeIpOrder_WithRandomizationEnabled_ShouldContainAllIps()
        {
            // Arrange
            var ips = new[]
            {
                IPAddress.Parse("192.168.1.1"),
                IPAddress.Parse("192.168.1.2"),
                IPAddress.Parse("192.168.1.3"),
                IPAddress.Parse("192.168.1.4"),
                IPAddress.Parse("192.168.1.5")
            };

            // Act
            var result = StealthScanner.RandomizeIpOrder(ips, true).ToArray();

            // Assert
            Assert.Equal(ips.Length, result.Length);
            
            // Check that all original IPs are present
            foreach (var ip in ips)
            {
                Assert.Contains(ip, result);
            }
        }

        [Fact]
        public async Task StealthScanner_AdaptiveDelay_WithFastResponse_ShouldApplyDelay()
        {
            // Arrange
            var config = new StealthConfig { MinScanDelay = 100, MaxScanDelay = 200 };
            var fastResponse = TimeSpan.FromMilliseconds(5);
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            // Act
            await StealthScanner.AdaptiveDelay(fastResponse, config);
            stopwatch.Stop();

            // Assert
            // Should take at least the minimum delay
            Assert.True(stopwatch.ElapsedMilliseconds >= 100, "Adaptive delay should apply extended delay for fast responses");
        }

        [Fact]
        public async Task StealthScanner_StealthPortScanAsync_WithInvalidTarget_ShouldReturnFalse()
        {
            // Arrange
            var config = StealthConfig.Default;
            var invalidTarget = IPAddress.Parse("192.0.2.1"); // RFC5737 test address, should not be reachable
            var port = 80;

            // Act
            var result = await StealthScanner.StealthPortScanAsync(invalidTarget, port, config);

            // Assert
            Assert.False(result, "Scan of unreachable target should return false");
        }

        [Fact]
        public void StealthScanner_TimingEvasion_CalculateOptimalTiming_ShouldReturnReasonableValue()
        {
            // Arrange
            var totalTargets = 100;
            var maxScanTime = TimeSpan.FromMinutes(5);

            // Act
            var timing = StealthScanner.TimingEvasion.CalculateOptimalTiming(totalTargets, maxScanTime);

            // Assert
            Assert.True(timing.TotalMilliseconds > 0, "Timing should be positive");
            Assert.True(timing.TotalMilliseconds < maxScanTime.TotalMilliseconds, "Timing should be less than max scan time");
        }

        [Fact]
        public async Task StealthScanner_TimingEvasion_ExponentialBackoff_ShouldIncreaseWithAttempts()
        {
            // Arrange & Act
            var stopwatch1 = System.Diagnostics.Stopwatch.StartNew();
            await StealthScanner.TimingEvasion.ExponentialBackoff(1);
            stopwatch1.Stop();

            var stopwatch2 = System.Diagnostics.Stopwatch.StartNew();
            await StealthScanner.TimingEvasion.ExponentialBackoff(3);
            stopwatch2.Stop();

            // Assert
            Assert.True(stopwatch2.ElapsedMilliseconds > stopwatch1.ElapsedMilliseconds, 
                "Higher attempt number should result in longer delay");
        }

        [Fact]
        public async Task StealthScanner_TrafficCamouflage_SimulateLegitimateTraffic_ShouldNotThrow()
        {
            // Arrange
            var config = StealthConfig.Default;

            // Act & Assert - Test passes if no exception is thrown
            await StealthScanner.TrafficCamouflage.SimulateLegitimateTraffic(config);
        }
    }
}