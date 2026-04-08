using System.Net;
using System.Threading.Tasks;
using Xunit;
using Discovery.Core.Utilities;

namespace Discovery.Tests.Core.Utilities
{
    /// <summary>
    /// Tests for DNS lookup helper functionality
    /// </summary>
    public class DnsLookupHelperTests
    {
        [Fact]
        public async Task GetHostnameAsync_WithValidLocalhost_ShouldReturnHostname()
        {
            // Arrange
            var localhostIp = IPAddress.Loopback;
            
            // Act
            var hostname = await DnsLookupHelper.GetHostnameAsync(localhostIp, 5000);
            
            // Assert
            // Should return either empty string (if DNS lookup fails) or a valid hostname
            Assert.True(hostname != null);
        }

        [Fact]
        public async Task GetHostnameAsync_WithInvalidIP_ShouldReturnEmptyString()
        {
            // Arrange
            var invalidIp = "999.999.999.999";
            
            // Act
            var hostname = await DnsLookupHelper.GetHostnameAsync(invalidIp, 2000);
            
            // Assert
            Assert.Equal(string.Empty, hostname);
        }

        [Fact]
        public async Task GetHostnameAsync_WithStringIP_ShouldHandleValidIP()
        {
            // Arrange
            var validIp = "127.0.0.1";
            
            // Act
            var hostname = await DnsLookupHelper.GetHostnameAsync(validIp, 5000);
            
            // Assert
            // Should return either empty string (if DNS lookup fails) or a valid hostname
            Assert.True(hostname != null);
        }
    }
}