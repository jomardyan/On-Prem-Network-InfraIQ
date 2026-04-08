using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using Discovery.Tools.Advanced;

namespace Discovery.Tests.Tools.Advanced
{
    /// <summary>
    /// Comprehensive tests for DNS enumeration functionality
    /// </summary>
    public class DnsEnumeratorTests
    {
        [Fact]
        public void DnsEnumerator_RecordTypes_ShouldNotBeNull()
        {
            // Act & Assert
            DnsEnumerator.RecordTypes.Should().NotBeNull();
            DnsEnumerator.RecordTypes.Should().NotBeEmpty();
        }

        [Theory]
        [InlineData("A")]
        [InlineData("AAAA")]
        [InlineData("MX")]
        [InlineData("NS")]
        [InlineData("CNAME")]
        [InlineData("TXT")]
        public void DnsEnumerator_RecordTypes_ShouldContainStandardTypes(string recordType)
        {
            // Act & Assert
            DnsEnumerator.RecordTypes.Should().ContainKey(recordType);
        }

        [Fact]
        public void DnsEnumerator_CommonSubdomains_ShouldNotBeNull()
        {
            // Act & Assert
            DnsEnumerator.CommonSubdomains.Should().NotBeNull();
            DnsEnumerator.CommonSubdomains.Should().NotBeEmpty();
        }

        [Fact]
        public void DnsEnumerator_StaticClass_ShouldExist()
        {
            // Act & Assert
            typeof(DnsEnumerator).Should().NotBeNull();
            typeof(DnsEnumerator).IsAbstract.Should().BeTrue();
            typeof(DnsEnumerator).IsSealed.Should().BeTrue();
        }
    }
}