using Xunit;
using Discovery.Core.Utilities;

namespace Discovery.Tests.Core
{
    /// <summary>
    /// Unit tests for the NetworkInputValidator utility class
    /// </summary>
    public class NetworkInputValidatorTests
    {
        [Theory]
        [InlineData("192.168.1.1", true)]
        [InlineData("10.0.0.1", true)]
        [InlineData("8.8.8.8", true)]
        [InlineData("127.0.0.1", true)]
        [InlineData("256.1.1.1", false)]
        [InlineData("192.168.1", false)]
        [InlineData("invalid", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsValidIpAddress_ShouldReturnExpectedResult(string? input, bool expected)
        {
            // Act
            var result = NetworkInputValidator.IsValidIpAddress(input);

            // Assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("192.168.1.0/24", true)]
        [InlineData("10.0.0.0/8", true)]
        [InlineData("172.16.0.0/12", true)]
        [InlineData("8.8.8.0/32", true)]
        [InlineData("192.168.1.0/33", false)]
        [InlineData("256.1.1.0/24", false)]
        [InlineData("192.168.1.0", false)]
        [InlineData("invalid/24", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsValidCidr_ShouldReturnExpectedResult(string? input, bool expected)
        {
            // Act
            var result = NetworkInputValidator.IsValidCidr(input);

            // Assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("80", true)]
        [InlineData("80,443", true)]
        [InlineData("80-90", true)]
        [InlineData("80,443,8080-8090", true)]
        [InlineData("1-65535", true)]
        [InlineData("0", false)]
        [InlineData("65536", false)]
        [InlineData("80-70", false)]
        [InlineData("80,", false)]
        [InlineData("80-", false)]
        [InlineData("-80", false)]
        [InlineData("invalid", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsValidPortRange_ShouldReturnExpectedResult(string? input, bool expected)
        {
            // Act
            var result = NetworkInputValidator.IsValidPortRange(input);

            // Assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("example.com", true)]
        [InlineData("google.com", true)]
        [InlineData("test.example.org", true)]
        [InlineData("a.b.c.d.e.f.g", true)]
        [InlineData("test-domain.com", true)]
        [InlineData("localhost", false)] // No dot - invalid for our stricter validation
        [InlineData(".example.com", false)]
        [InlineData("example.com.", false)]
        [InlineData("ex ample.com", false)]
        [InlineData("invalid", false)] // No dot - invalid
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsValidDomain_ShouldReturnExpectedResult(string? input, bool expected)
        {
            // Act
            var result = NetworkInputValidator.IsValidDomain(input);

            // Assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("192.168.1.1", true)]
        [InlineData("example.com", true)]
        [InlineData("google.com", true)]
        [InlineData("8.8.8.8", true)]
        [InlineData("invalid", false)]
        [InlineData("256.1.1.1", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsValidTarget_ShouldReturnExpectedResult(string? input, bool expected)
        {
            // Act
            var result = NetworkInputValidator.IsValidTarget(input);

            // Assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("192.168.1.1", true)]
        [InlineData("10.0.0.1", true)]
        [InlineData("172.16.0.1", true)]
        [InlineData("127.0.0.1", true)]
        [InlineData("8.8.8.8", false)]
        [InlineData("1.1.1.1", false)]
        [InlineData("173.16.0.1", false)]
        [InlineData("192.167.1.1", false)]
        [InlineData("invalid", false)]
        public void IsPrivateIpAddress_ShouldReturnExpectedResult(string input, bool expected)
        {
            // Act
            var result = NetworkInputValidator.IsPrivateIpAddress(input);

            // Assert
            Assert.Equal(expected, result);
        }

        [Fact]
        public void GetValidationErrorMessage_ShouldReturnFormattedMessage()
        {
            // Arrange
            var input = "invalid";
            var inputType = "IP";

            // Act
            var result = NetworkInputValidator.GetValidationErrorMessage(input, inputType);

            // Assert
            Assert.Contains(input, result);
            Assert.Contains("not a valid IP address", result);
        }

        [Theory]
        [InlineData("invalid", "ip", "not a valid IP address")]
        [InlineData("invalid", "cidr", "not valid CIDR notation")]
        [InlineData("invalid", "port", "not a valid port specification")]
        [InlineData("invalid", "domain", "not a valid domain name")]
        [InlineData("invalid", "target", "not a valid IP address or domain name")]
        public void GetValidationErrorMessage_ShouldReturnCorrectMessageForInputType(string input, string inputType, string expectedContent)
        {
            // Act
            var result = NetworkInputValidator.GetValidationErrorMessage(input, inputType);

            // Assert
            Assert.Contains(expectedContent, result);
        }
    }
}