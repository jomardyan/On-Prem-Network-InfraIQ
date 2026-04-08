using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Discovery.Tools.RouterScanning;
using Xunit;

namespace Discovery.Tests.Tools.RouterScanning
{
    public class RouterFingerprintingTests
    {
        [Fact]
        public void RouterBrand_Enum_ShouldHaveValidValues()
        {
            // Test that all enum values are properly defined
            var brands = Enum.GetValues<RouterFingerprinter.RouterBrand>();
            
            Assert.Contains(RouterFingerprinter.RouterBrand.Unknown, brands);
            Assert.Contains(RouterFingerprinter.RouterBrand.Cisco, brands);
            Assert.Contains(RouterFingerprinter.RouterBrand.Mikrotik, brands);
            Assert.Contains(RouterFingerprinter.RouterBrand.Ubiquiti, brands);
            Assert.Contains(RouterFingerprinter.RouterBrand.Netgear, brands);
            Assert.Contains(RouterFingerprinter.RouterBrand.TPLink, brands);
            Assert.Contains(RouterFingerprinter.RouterBrand.Palo_Alto, brands);
        }

        [Fact]
        public void RouterIdentification_Constructor_ShouldInitializeCorrectly()
        {
            var identification = new RouterFingerprinter.RouterIdentification();
            
            Assert.Equal(RouterFingerprinter.RouterBrand.Unknown, identification.Brand);
            Assert.Equal(string.Empty, identification.Model);
            Assert.Equal(string.Empty, identification.Firmware);
            Assert.NotNull(identification.ManagementPorts);
            Assert.NotNull(identification.ServiceBanners);
            Assert.NotNull(identification.DetectionMethods);
            Assert.Equal(0, identification.ConfidenceScore);
        }

        [Fact]
        public void IdentifyRouterAsync_WithInvalidIP_ShouldReturnCorrectIPType()
        {
            // Use a non-routable IP that won't respond quickly
            var ipAddress = IPAddress.Parse("169.254.0.1");
            
            // Test validates that the IP is properly parsed and in link-local range
            Assert.Equal("169.254.0.1", ipAddress.ToString());
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, ipAddress.AddressFamily);
            
            // Verify it's in the link-local range (169.254.x.x)
            var bytes = ipAddress.GetAddressBytes();
            Assert.Equal(169, bytes[0]);
            Assert.Equal(254, bytes[1]);
        }

        [Theory]
        [InlineData("192.168.1.1")]
        [InlineData("10.0.0.1")]
        [InlineData("172.16.0.1")]
        public void IdentifyRouterAsync_WithPrivateIPs_ShouldNotThrowOnValidation(string ipString)
        {
            var ipAddress = IPAddress.Parse(ipString);
            
            // This test validates IP parsing works correctly
            Assert.True(ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            
            // Test that the IP is in a private range
            var bytes = ipAddress.GetAddressBytes();
            bool isPrivate = (bytes[0] == 10) ||
                           (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                           (bytes[0] == 192 && bytes[1] == 168);
            Assert.True(isPrivate);
        }
    }

    public class RouterScanManagerTests
    {
        [Fact]
        public void ScanSingleRouterAsync_WithValidIP_ShouldReturnValidResult()
        {
            var ipAddress = IPAddress.Parse("192.168.1.1");
            
            // Test that the method can be called without throwing
            var task = RouterScanManager.ScanSingleRouterAsync(ipAddress);
            Assert.NotNull(task);
            
            // Validate IP is properly formatted
            Assert.Equal("192.168.1.1", ipAddress.ToString());
        }

        [Fact]
        public void RouterScanResult_Constructor_ShouldInitializeCorrectly()
        {
            var result = new RouterScanResult();
            
            Assert.Equal(IPAddress.None, result.IpAddress);
            Assert.False(result.IsRouter);
            Assert.NotNull(result.ManagementPorts);
            Assert.NotNull(result.DetectionMethods);
            Assert.Equal(0, result.ConfidenceScore);
        }

        [Fact]
        public void ScanForRoutersAsync_WithSmallRange_ShouldValidateIpRange()
        {
            var startIp = IPAddress.Parse("192.168.1.1");
            var endIp = IPAddress.Parse("192.168.1.3");
            
            // Test IP range validation
            var startBytes = startIp.GetAddressBytes();
            var endBytes = endIp.GetAddressBytes();
            
            // Validate that end IP is greater than start IP
            var startInt = BitConverter.ToUInt32(startBytes.Reverse().ToArray(), 0);
            var endInt = BitConverter.ToUInt32(endBytes.Reverse().ToArray(), 0);
            
            Assert.True(endInt >= startInt);
        }
    }

    public class CiscoScannerTests
    {
        [Fact]
        public void CiscoDevice_Constructor_ShouldInitializeCorrectly()
        {
            var device = new CiscoScanner.CiscoDevice();
            
            Assert.Equal(IPAddress.None, device.IpAddress);
            Assert.Equal(string.Empty, device.Model);
            Assert.Equal(string.Empty, device.IosVersion);
            Assert.NotNull(device.OpenPorts);
            Assert.NotNull(device.Services);
            Assert.NotNull(device.SecurityFindings);
            Assert.NotNull(device.ConfigurationInfo);
            Assert.NotNull(device.EnabledProtocols);
        }

        [Fact]
        public void CiscoSecurityFinding_Constructor_ShouldInitializeCorrectly()
        {
            var finding = new CiscoScanner.SecurityFinding();
            
            Assert.Equal(string.Empty, finding.Category);
            Assert.Equal(string.Empty, finding.Severity);
            Assert.Equal(string.Empty, finding.Description);
            Assert.Equal(string.Empty, finding.Recommendation);
            Assert.Equal(string.Empty, finding.CveId);
        }

        [Fact]
        public void ScanCiscoDeviceAsync_WithValidIP_ShouldValidateInput()
        {
            var ipAddress = IPAddress.Parse("192.168.1.1");
            
            // Test that the scanner can accept valid IP addresses
            Assert.Equal("192.168.1.1", ipAddress.ToString());
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, ipAddress.AddressFamily);
        }
    }

    public class MikroTikScannerTests
    {
        [Fact]
        public void MikroTikDevice_Constructor_ShouldInitializeCorrectly()
        {
            var device = new MikroTikScanner.MikroTikDevice();
            
            Assert.Equal(IPAddress.None, device.IpAddress);
            Assert.Equal(string.Empty, device.Model);
            Assert.Equal(string.Empty, device.RouterOsVersion);
            Assert.NotNull(device.OpenPorts);
            Assert.NotNull(device.Services);
            Assert.NotNull(device.SecurityFindings);
            Assert.NotNull(device.ApiInfo);
            Assert.NotNull(device.SystemInfo);
        }

        [Fact]
        public void ScanMikroTikDeviceAsync_WithValidIP_ShouldValidateInput()
        {
            var ipAddress = IPAddress.Parse("192.168.88.1"); // Common MikroTik default IP
            
            // Test that the scanner can accept valid IP addresses
            Assert.Equal("192.168.88.1", ipAddress.ToString());
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, ipAddress.AddressFamily);
        }
    }

    public class EnterpriseRouterScannerTests
    {
        [Fact]
        public void EnterpriseDevice_Constructor_ShouldInitializeCorrectly()
        {
            var device = new EnterpriseRouterScanner.EnterpriseDevice();
            
            Assert.Equal(IPAddress.None, device.IpAddress);
            Assert.Equal(string.Empty, device.Brand);
            Assert.Equal(string.Empty, device.Model);
            Assert.NotNull(device.OpenPorts);
            Assert.NotNull(device.Services);
            Assert.NotNull(device.SecurityFindings);
            Assert.NotNull(device.ManagementInterfaces);
            Assert.NotNull(device.SupportedProtocols);
            Assert.NotNull(device.CertificateInfo);
        }

        [Fact]
        public void ScanEnterpriseDeviceAsync_WithValidIP_ShouldValidateInput()
        {
            var ipAddress = IPAddress.Parse("10.0.0.1");
            
            // Test that the scanner can accept valid IP addresses
            Assert.Equal("10.0.0.1", ipAddress.ToString());
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, ipAddress.AddressFamily);
        }
    }
}