using System;
using System.Linq;
using System.Net;
using Xunit;
using FluentAssertions;
using Discovery.Tools;

namespace Discovery.Tests.Tools
{
    public class NetworkCalculatorTests
    {
        [Fact]
        public void CalculateNetwork_BasicIPv4_ShouldReturnCorrectResults()
        {
            // Arrange
            var ipAddress = IPAddress.Parse("192.168.1.100");
            var subnetMask = IPAddress.Parse("255.255.255.0");

            // Act
            var result = NetworkCalculator.CalculateNetwork(ipAddress, subnetMask);

            // Assert
            result.IpAddress.Should().Be(ipAddress);
            result.SubnetMask.Should().Be(subnetMask);
            result.NetworkAddress.Should().Be(IPAddress.Parse("192.168.1.0"));
            result.BroadcastAddress.Should().Be(IPAddress.Parse("192.168.1.255"));
            result.FirstUsableIp.Should().Be(IPAddress.Parse("192.168.1.1"));
            result.LastUsableIp.Should().Be(IPAddress.Parse("192.168.1.254"));
            result.PrefixLength.Should().Be(24);
            result.TotalHosts.Should().Be(256);
            result.UsableHosts.Should().Be(254);
            result.NetworkClass.Should().Be("Class C");
            result.IsPrivate.Should().BeTrue();
        }

        [Fact]
        public void CalculateNetworkFromCidr_ValidCidr_ShouldReturnCorrectResults()
        {
            // Arrange
            var cidr = "10.0.0.0/8";

            // Act
            var result = NetworkCalculator.CalculateNetworkFromCidr(cidr);

            // Assert
            result.NetworkAddress.Should().Be(IPAddress.Parse("10.0.0.0"));
            result.BroadcastAddress.Should().Be(IPAddress.Parse("10.255.255.255"));
            result.PrefixLength.Should().Be(8);
            result.TotalHosts.Should().Be(16777216); // 2^24
            result.UsableHosts.Should().Be(16777214);
            result.NetworkClass.Should().Be("Class A");
            result.IsPrivate.Should().BeTrue();
        }

        [Fact]
        public void CalculatePrefixLength_StandardSubnetMasks_ShouldReturnCorrectValues()
        {
            // Arrange & Act & Assert
            NetworkCalculator.CalculatePrefixLength(IPAddress.Parse("255.255.255.0")).Should().Be(24);
            NetworkCalculator.CalculatePrefixLength(IPAddress.Parse("255.255.0.0")).Should().Be(16);
            NetworkCalculator.CalculatePrefixLength(IPAddress.Parse("255.0.0.0")).Should().Be(8);
            NetworkCalculator.CalculatePrefixLength(IPAddress.Parse("255.255.255.128")).Should().Be(25);
            NetworkCalculator.CalculatePrefixLength(IPAddress.Parse("255.255.255.192")).Should().Be(26);
        }

        [Fact]
        public void CreateSubnetMask_ValidPrefixLengths_ShouldReturnCorrectMasks()
        {
            // Arrange & Act & Assert
            var mask24 = NetworkCalculator.CreateSubnetMask(24, System.Net.Sockets.AddressFamily.InterNetwork);
            mask24.Should().Be(IPAddress.Parse("255.255.255.0"));

            var mask16 = NetworkCalculator.CreateSubnetMask(16, System.Net.Sockets.AddressFamily.InterNetwork);
            mask16.Should().Be(IPAddress.Parse("255.255.0.0"));

            var mask8 = NetworkCalculator.CreateSubnetMask(8, System.Net.Sockets.AddressFamily.InterNetwork);
            mask8.Should().Be(IPAddress.Parse("255.0.0.0"));

            var mask25 = NetworkCalculator.CreateSubnetMask(25, System.Net.Sockets.AddressFamily.InterNetwork);
            mask25.Should().Be(IPAddress.Parse("255.255.255.128"));
        }

        [Fact]
        public void GetIpAddressesInSubnet_SmallSubnet_ShouldReturnCorrectIps()
        {
            // Arrange
            var networkInfo = NetworkCalculator.CalculateNetworkFromCidr("192.168.1.0/30");

            // Act
            var ips = NetworkCalculator.GetIpAddressesInSubnet(networkInfo, false).ToList();

            // Assert
            ips.Should().HaveCount(2);
            ips[0].Should().Be(IPAddress.Parse("192.168.1.1"));
            ips[1].Should().Be(IPAddress.Parse("192.168.1.2"));
        }

        [Fact]
        public void IsIpInSubnet_IpInSubnet_ShouldReturnTrue()
        {
            // Arrange
            var networkInfo = NetworkCalculator.CalculateNetworkFromCidr("192.168.1.0/24");
            var testIp = IPAddress.Parse("192.168.1.50");

            // Act
            var result = NetworkCalculator.IsIpInSubnet(testIp, networkInfo);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void IsIpInSubnet_IpNotInSubnet_ShouldReturnFalse()
        {
            // Arrange
            var networkInfo = NetworkCalculator.CalculateNetworkFromCidr("192.168.1.0/24");
            var testIp = IPAddress.Parse("192.168.2.50");

            // Act
            var result = NetworkCalculator.IsIpInSubnet(testIp, networkInfo);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void CalculateNetworkFromCidr_InvalidCidr_ShouldThrowArgumentException()
        {
            // Arrange
            var invalidCidr = "invalid-cidr";

            // Act & Assert
            Assert.Throws<ArgumentException>(() => NetworkCalculator.CalculateNetworkFromCidr(invalidCidr));
        }

        [Fact] 
        public void CreateSubnetMask_InvalidPrefixLength_ShouldThrowArgumentException()
        {
            // Arrange
            var invalidPrefixLength = 33; // IPv4 max is 32

            // Act & Assert
            Assert.Throws<ArgumentException>(() => 
                NetworkCalculator.CreateSubnetMask(invalidPrefixLength, System.Net.Sockets.AddressFamily.InterNetwork));
        }

        [Theory]
        [InlineData("172.31.255.1", true)]  // 172.16.0.0/12 - private
        [InlineData("172.15.255.1", false)] // Just outside private range
        [InlineData("172.32.0.1", false)]   // Just outside private range
        [InlineData("169.254.1.1", false)]  // Link-local, not private RFC1918
        public void CalculateNetwork_PrivateIPDetection_ShouldDetectCorrectly(string ipString, bool expectedIsPrivate)
        {
            // Arrange
            var ipAddress = IPAddress.Parse(ipString);
            var subnetMask = IPAddress.Parse("255.255.255.0");

            // Act
            var result = NetworkCalculator.CalculateNetwork(ipAddress, subnetMask);

            // Assert
            result.IsPrivate.Should().Be(expectedIsPrivate);
        }

        [Fact]
        public void NetworkInfo_Properties_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var networkInfo = new Discovery.Tools.NetworkInfo();

            // Assert
            networkInfo.IpAddress.Should().Be(IPAddress.None);
            networkInfo.SubnetMask.Should().Be(IPAddress.None);
            networkInfo.NetworkAddress.Should().Be(IPAddress.None);
            networkInfo.BroadcastAddress.Should().Be(IPAddress.None);
            networkInfo.FirstUsableIp.Should().BeNull();
            networkInfo.LastUsableIp.Should().BeNull();
            networkInfo.PrefixLength.Should().Be(0);
            networkInfo.TotalHosts.Should().Be(0);
            networkInfo.UsableHosts.Should().Be(0);
            networkInfo.NetworkClass.Should().BeEmpty();
            networkInfo.IsPrivate.Should().BeFalse();
        }
    }
}
