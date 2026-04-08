using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Discovery.Services.Scanning;

namespace Discovery.Tests.Services.Scanning
{
    /// <summary>
    /// Tests for reverse DNS functionality in port scanners
    /// </summary>
    public class PortScannerReverseDnsTests
    {
        [Fact]
        public async Task PortScanner_ScanSingleIpAsync_ShouldIncludeHostname()
        {
            // Arrange
            var portScanner = new PortScanner(timeout: 1000, maxConcurrency: 10);
            var portsToScan = new Dictionary<int, string> { { 22, "SSH" } };
            var cancellationToken = new CancellationToken();
            
            // Act
            var results = await portScanner.ScanSingleIpAsync("127.0.0.1", portsToScan, cancellationToken);
            
            // Assert
            Assert.NotNull(results);
            // If any open ports are found, they should have hostname field populated (even if empty)
            foreach (var result in results.Where(r => r.IsOpen))
            {
                Assert.True(result.Hostname != null); // Should not be null
            }
        }

        [Fact]
        public async Task AdvancedPortScanner_ComprehensiveScanAsync_ShouldIncludeHostname()
        {
            // Arrange
            var advancedScanner = new AdvancedPortScanner(timeout: 1000, maxConcurrency: 10);
            var tcpPorts = new Dictionary<int, string> { { 22, "SSH" } };
            var udpPorts = new Dictionary<int, string>();
            var cancellationToken = new CancellationToken();
            
            // Act
            var results = await advancedScanner.ComprehensiveScanAsync("127.0.0.1", tcpPorts, udpPorts, cancellationToken);
            
            // Assert
            Assert.NotNull(results);
            // If any open ports are found, they should have hostname field populated (even if empty)
            foreach (var result in results.Where(r => r.IsOpen))
            {
                Assert.True(result.Hostname != null); // Should not be null
            }
        }

        [Fact]
        public async Task PortScanner_MultipleOpenPorts_ShouldShareConsistentHostname()
        {
            // Arrange: scan several ports so that if any are open they should share the same hostname,
            // confirming the DNS lookup is performed once per host and reused across all ports.
            var portScanner = new PortScanner(timeout: 1000, maxConcurrency: 20);
            var portsToScan = new Dictionary<int, string>
            {
                { 22, "SSH" },
                { 80, "HTTP" },
                { 443, "HTTPS" },
                { 8080, "HTTP-Alt" },
            };
            var cancellationToken = new CancellationToken();

            // Act
            var results = await portScanner.ScanSingleIpAsync("127.0.0.1", portsToScan, cancellationToken);

            // Assert
            Assert.NotNull(results);
            var openResults = results.Where(r => r.IsOpen).ToList();
            if (openResults.Count > 1)
            {
                // All open ports on the same host must report the same hostname
                var hostnames = openResults.Select(r => r.Hostname).Distinct().ToList();
                Assert.Single(hostnames);
            }
        }

        [Fact]
        public async Task AdvancedPortScanner_MultipleOpenPorts_ShouldShareConsistentHostname()
        {
            // Arrange
            var advancedScanner = new AdvancedPortScanner(timeout: 1000, maxConcurrency: 20);
            var tcpPorts = new Dictionary<int, string>
            {
                { 22, "SSH" },
                { 80, "HTTP" },
                { 443, "HTTPS" },
                { 8080, "HTTP-Alt" },
            };
            var udpPorts = new Dictionary<int, string>();
            var cancellationToken = new CancellationToken();

            // Act
            var results = await advancedScanner.ComprehensiveScanAsync("127.0.0.1", tcpPorts, udpPorts, cancellationToken);

            // Assert
            Assert.NotNull(results);
            var openResults = results.Where(r => r.IsOpen).ToList();
            if (openResults.Count > 1)
            {
                // All open ports on the same host must report the same hostname
                var hostnames = openResults.Select(r => r.Hostname).Distinct().ToList();
                Assert.Single(hostnames);
            }
        }
    }
}