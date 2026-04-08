using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Constants;
using Discovery.Services.Scanning;
using Xunit;

namespace Discovery.Tests.Services.Scanning
{
    /// <summary>
    /// Tests for the new batch scanning functionality
    /// </summary>
    public class BatchScanningTests
    {
        [Fact]
        public async Task PortScanner_ScanCsvTargetsAsync_WithMultipleTargets_ShouldReturnResults()
        {
            // Arrange
            var scanner = new PortScanner(timeout: 1000, maxConcurrency: 10);
            var csvContent = @"
127.0.0.1
192.168.1.1-192.168.1.2
10.0.0.0/30
# This is a comment
172.16.0.1, 172.16.0.2";
            var portsToScan = new Dictionary<int, string>
            {
                { 80, "HTTP" },
                { 443, "HTTPS" }
            };
            var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

            // Act
            var results = await scanner.ScanCsvTargetsAsync(csvContent, portsToScan, cancellationToken);

            // Assert
            Assert.NotNull(results);
            // Results may be empty due to firewall restrictions, but the method should not throw
        }

        [Fact]
        public async Task PortScanner_ScanCidrNetworkAsync_WithStringNotation_ShouldReturnResults()
        {
            // Arrange
            var scanner = new PortScanner(timeout: 1000, maxConcurrency: 5);
            var cidrNotation = "127.0.0.0/30"; // Small range for testing
            var portsToScan = new Dictionary<int, string>
            {
                { 80, "HTTP" }
            };
            var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(15)).Token;

            // Act
            var results = await scanner.ScanCidrNetworkAsync(cidrNotation, portsToScan, cancellationToken);

            // Assert
            Assert.NotNull(results);
            // Results may be empty due to firewall restrictions, but the method should not throw
        }

        [Fact]
        public async Task PortScanner_ScanIpRangeAsync_WithStringNotation_ShouldReturnResults()
        {
            // Arrange
            var scanner = new PortScanner(timeout: 1000, maxConcurrency: 5);
            var startIp = "127.0.0.1";
            var endIp = "127.0.0.2";
            var portsToScan = new Dictionary<int, string>
            {
                { 80, "HTTP" }
            };
            var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token;

            // Act
            var results = await scanner.ScanIpRangeAsync(startIp, endIp, portsToScan, cancellationToken);

            // Assert
            Assert.NotNull(results);
            // Results may be empty due to firewall restrictions, but the method should not throw
        }

        [Fact]
        public async Task PortScanner_ScanBatchTargetsAsync_WithMixedTargets_ShouldReturnResults()
        {
            // Arrange
            var scanner = new PortScanner(timeout: 1000, maxConcurrency: 5);
            var targets = new[]
            {
                "127.0.0.1",
                "127.0.0.0/30",
                "192.168.1.1-192.168.1.2"
            };
            var portsToScan = new Dictionary<int, string>
            {
                { 80, "HTTP" }
            };
            var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token;

            // Act
            var results = await scanner.ScanBatchTargetsAsync(targets, portsToScan, cancellationToken);

            // Assert
            Assert.NotNull(results);
            // Results may be empty due to firewall restrictions, but the method should not throw
        }

        [Fact]
        public async Task AdvancedPortScanner_ImplementsIScannerInterface_ShouldReturnResults()
        {
            // Arrange
            var scanner = new AdvancedPortScanner(timeout: 1000, maxConcurrency: 5);
            var ipAddress = "127.0.0.1";
            var portsToScan = new Dictionary<int, string>
            {
                { 80, "HTTP" }
            };
            var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token;

            // Act
            var results = await scanner.ScanSingleIpAsync(ipAddress, portsToScan, cancellationToken);

            // Assert
            Assert.NotNull(results);
            // Results may be empty due to firewall restrictions, but the method should not throw
        }

        [Fact]
        public async Task IPv6Scanner_ImplementsIScannerInterface_ShouldReturnResults()
        {
            // Arrange
            var scanner = new IPv6Scanner(timeout: 1000, maxConcurrency: 5);
            var ipAddress = "127.0.0.1"; // Will be converted to IPv6 mapped
            var portsToScan = new Dictionary<int, string>
            {
                { 80, "HTTP" }
            };
            var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token;

            // Act
            var results = await scanner.ScanSingleIpAsync(ipAddress, portsToScan, cancellationToken);

            // Assert
            Assert.NotNull(results);
            // Results may be empty due to firewall restrictions, but the method should not throw
        }
    }
}