/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

using Xunit;
using Discovery.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Net;

namespace Discovery.Tests.Security
{
    /// <summary>
    /// Tests for CCTV scanner functionality
    /// </summary>
    public class CctvScannerTests
    {
        [Fact]
        public async Task ScanSingleIpAsync_ValidLocalhostIp_ShouldReturnResults()
        {
            // Arrange
            using var scanner = new CctvScanner();
            var ipAddress = "127.0.0.1";
            var ports = new Dictionary<int, string>();

            // Act
            var results = await scanner.ScanSingleIpAsync(ipAddress, ports, CancellationToken.None);

            // Assert
            Assert.NotNull(results);
            // Results might be empty since localhost likely doesn't have CCTV devices, but scanner should work
        }

        [Fact]
        public async Task ScanCidrNetworkAsync_ValidSmallNetwork_ShouldReturnResults()
        {
            // Arrange
            using var scanner = new CctvScanner();
            var cidrNetwork = "127.0.0.0/30"; // Very small network for testing
            var ports = new Dictionary<int, string>();

            // Act
            var results = await scanner.ScanCidrNetworkAsync(cidrNetwork, ports, CancellationToken.None);

            // Assert
            Assert.NotNull(results);
        }

        [Fact]
        public async Task ScanIpRangeAsync_ValidRange_ShouldReturnResults()
        {
            // Arrange
            using var scanner = new CctvScanner();
            var startIp = "127.0.0.1";
            var endIp = "127.0.0.2";
            var ports = new Dictionary<int, string>();

            // Act
            var results = await scanner.ScanIpRangeAsync(startIp, endIp, ports, CancellationToken.None);

            // Assert
            Assert.NotNull(results);
        }

        [Fact]
        public async Task ScanCsvTargetsAsync_ValidCsv_ShouldReturnResults()
        {
            // Arrange
            using var scanner = new CctvScanner();
            var csvContent = "127.0.0.1\n127.0.0.2";
            var ports = new Dictionary<int, string>();

            // Act
            var results = await scanner.ScanCsvTargetsAsync(csvContent, ports, CancellationToken.None);

            // Assert
            Assert.NotNull(results);
        }

        [Fact]
        public async Task ScanBatchTargetsAsync_ValidTargets_ShouldReturnResults()
        {
            // Arrange
            using var scanner = new CctvScanner();
            var targets = new[] { "127.0.0.1", "127.0.0.2" };
            var ports = new Dictionary<int, string>();

            // Act
            var results = await scanner.ScanBatchTargetsAsync(targets, ports, CancellationToken.None);

            // Assert
            Assert.NotNull(results);
        }

        [Fact]
        public void CctvScanner_CanBeDisposed_ShouldNotThrow()
        {
            // Arrange & Act & Assert
            using var scanner = new CctvScanner();
            // Should not throw when disposed
        }
    }
}