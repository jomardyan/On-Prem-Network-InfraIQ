using System.Net;
using Discovery.Core.Models;
using Discovery.Security;
using Xunit;

namespace Discovery.Tests.Security
{
    public class HoneypotDetectorTests
    {
        [Fact]
        public void AnalyzePotentialHoneypot_WithExcessiveOpenPorts_ShouldDetectThreat()
        {
            // Arrange
            var target = IPAddress.Parse("192.168.1.100");
            var scanResults = new List<ScanResult>();
            
            // Create 60 open ports (suspicious)
            for (int i = 1; i <= 60; i++)
            {
                scanResults.Add(new ScanResult(
                    target,
                    i,
                    true,
                    $"Service{i}",
                    10
                ));
            }

            // Act
            var result = HoneypotDetector.AnalyzePotentialHoneypot(target, scanResults);

            // Assert
            Assert.True(result.SuspicionScore > 0);
            Assert.True(result.ThreatLevel != ThreatLevel.None);
            Assert.Contains(result.Indicators, i => i.Contains("Excessive open ports"));
        }

        [Fact]
        public void AnalyzePotentialHoneypot_WithNormalPorts_ShouldShowLowThreat()
        {
            // Arrange
            var target = IPAddress.Parse("192.168.1.100");
            var scanResults = new List<ScanResult>
            {
                new(target, 80, true, "HTTP", 15),
                new(target, 443, true, "HTTPS", 12),
                new(target, 22, true, "SSH", 8)
            };

            // Act
            var result = HoneypotDetector.AnalyzePotentialHoneypot(target, scanResults);

            // Assert
            Assert.Equal(ThreatLevel.None, result.ThreatLevel);
            Assert.Equal(0, result.SuspicionScore);
        }

        [Fact]
        public void AnalyzePotentialHoneypot_WithSuspiciousServiceCombination_ShouldDetectThreat()
        {
            // Arrange
            var target = IPAddress.Parse("192.168.1.100");
            var scanResults = new List<ScanResult>
            {
                new(target, 21, true, "ftp", 10),
                new(target, 23, true, "telnet", 10),
                new(target, 25, true, "smtp", 10)
                // This combination should trigger the suspicious service detection
            };

            // Act
            var result = HoneypotDetector.AnalyzePotentialHoneypot(target, scanResults);

            // Assert
            Assert.True(result.SuspicionScore > 0);
            Assert.Contains(result.Indicators, i => i.Contains("service combination"));
        }

        [Fact]
        public async Task IsLikelyHoneypotAsync_WithUnreachableTarget_ShouldReturnFalse()
        {
            // Arrange
            var unreachableTarget = IPAddress.Parse("192.0.2.1"); // RFC5737 test address

            // Act
            var result = await HoneypotDetector.IsLikelyHoneypotAsync(unreachableTarget, 1000);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void HoneypotAnalysisResult_ShouldHaveCorrectProperties()
        {
            // Arrange
            var target = IPAddress.Parse("192.168.1.100");
            var indicators = new List<string> { "Test indicator" };
            var recommendations = new List<string> { "Test recommendation" };

            // Act
            var result = new HoneypotAnalysisResult
            {
                Target = target.ToString(),
                SuspicionScore = 15,
                ThreatLevel = ThreatLevel.Medium,
                Indicators = indicators,
                Recommendations = recommendations
            };

            // Assert
            Assert.Equal(target.ToString(), result.Target);
            Assert.Equal(15, result.SuspicionScore);
            Assert.Equal(ThreatLevel.Medium, result.ThreatLevel);
            Assert.Equal(indicators, result.Indicators);
            Assert.Equal(recommendations, result.Recommendations);
        }

        [Theory]
        [InlineData(ThreatLevel.None)]
        [InlineData(ThreatLevel.Low)]
        [InlineData(ThreatLevel.Medium)]
        [InlineData(ThreatLevel.High)]
        public void ThreatLevel_ShouldHaveAllExpectedValues(ThreatLevel level)
        {
            // This test ensures all enum values are covered
            Assert.True(Enum.IsDefined(typeof(ThreatLevel), level));
        }
    }
}