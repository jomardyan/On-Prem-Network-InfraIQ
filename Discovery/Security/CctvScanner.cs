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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Discovery.Core.Utilities;
using Discovery.Services.Scanning;
using Spectre.Console;

namespace Discovery.Security
{
    /// <summary>
    /// Advanced CCTV, DVR, and IP camera scanner with authentication testing
    /// Detects surveillance devices and tests for default/weak credentials
    /// </summary>
    public class CctvScanner : BaseBatchScanner, IScanner, IDisposable
    {
        private readonly SemaphoreSlim _semaphore;
        private readonly HttpClient _httpClient;
        private readonly Dictionary<int, string> _cctvPorts;
        private static readonly Dictionary<string, List<DefaultCredential>> DefaultCctvCredentials = InitializeDefaultCredentials();

        /// <summary>
        /// Initializes a new instance of the CctvScanner class
        /// </summary>
        public CctvScanner(int maxConcurrency = 20)
        {
            _semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            _cctvPorts = InitializeCctvPorts();
        }

        /// <summary>
        /// Scans for CCTV devices and tests credentials on a single IP address
        /// </summary>
        public async Task<List<ScanResult>> ScanSingleIpAsync(string ipAddress, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var results = new List<ScanResult>();
            var ports = portsToScan?.Any() == true ? portsToScan : _cctvPorts;

            foreach (var port in ports)
            {
                if (cancellationToken.IsCancellationRequested) break;

                var result = await ScanSinglePortAsync(ipAddress, port.Key, port.Value, cancellationToken);
                if (result.HasValue)
                    results.Add(result.Value);
            }

            return results;
        }

        /// <summary>
        /// Scans a network range for CCTV devices
        /// </summary>
        public async Task<List<ScanResult>> ScanNetworkRangeAsync(string baseIp, int startRange, int endRange, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var results = new ConcurrentBag<ScanResult>();
            var ports = portsToScan?.Any() == true ? portsToScan : _cctvPorts;
            var tasks = new List<Task>();

            for (int i = startRange; i <= endRange; i++)
            {
                if (cancellationToken.IsCancellationRequested) break;

                var targetIp = $"{baseIp}.{i}";
                tasks.Add(ScanIpForCctvDevices(targetIp, ports, results, cancellationToken));
            }

            await Task.WhenAll(tasks);
            return results.ToList();
        }

        /// <summary>
        /// Scans a CIDR network for CCTV devices
        /// </summary>
        public async Task<List<ScanResult>> ScanCidrNetworkAsync(IPAddress networkAddress, int subnetMask, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var ipList = ExpandCidrToIps($"{networkAddress}/{subnetMask}").ToList();
            return await ScanIpListAsync(ipList, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans a CIDR network using string notation for CCTV devices
        /// </summary>
        public async Task<List<ScanResult>> ScanCidrNetworkAsync(string cidrNotation, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var ipList = ExpandCidrToIps(cidrNotation).ToList();
            return await ScanIpListAsync(ipList, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans a range of public IP addresses for CCTV devices
        /// </summary>
        public async Task<List<ScanResult>> ScanPublicIpRangeAsync(IPAddress startIp, IPAddress endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var ipList = GetIpRange(startIp, endIp).ToList();
            return await ScanIpListAsync(ipList, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans a range of IP addresses using string notation for CCTV devices
        /// </summary>
        public async Task<List<ScanResult>> ScanIpRangeAsync(string startIp, string endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            if (!IPAddress.TryParse(startIp, out var startAddress) || !IPAddress.TryParse(endIp, out var endAddress))
                return new List<ScanResult>();
                
            var ipList = GetIpRange(startAddress, endAddress).ToList();
            return await ScanIpListAsync(ipList, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans multiple targets from a CSV list for CCTV devices
        /// </summary>
        public async Task<List<ScanResult>> ScanCsvTargetsAsync(string csvContent, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var targets = ParseCsvTargets(csvContent);
            return await ScanBatchTargetsAsync(targets, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans multiple targets from a list of target strings for CCTV devices
        /// </summary>
        public async Task<List<ScanResult>> ScanBatchTargetsAsync(IEnumerable<string> targets, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var allResults = new ConcurrentBag<ScanResult>();
            var expandedIps = ExpandTargetsToIps(targets).ToList();
            var ports = portsToScan?.Any() == true ? portsToScan : _cctvPorts;

            // Safety check for large scans
            if (!TestEnvironmentDetector.IsTestEnvironment && expandedIps.Count > 100)
            {
                if (!TestEnvironmentDetector.IsTestEnvironment)
                {
                    var confirm = AnsiConsole.Confirm($"[yellow]⚠️ This will scan {expandedIps.Count} IP addresses for CCTV devices. Continue?[/]");
                    if (!confirm) return new List<ScanResult>();
                }
            }

            var concurrencyLimit = Math.Min(20, expandedIps.Count);
            using var semaphore = new SemaphoreSlim(concurrencyLimit, concurrencyLimit);

            var tasks = expandedIps.Select(async ip =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    await ScanIpForCctvDevices(ip, ports, allResults, cancellationToken);
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);
            return allResults.ToList();
        }

        /// <summary>
        /// Scans a single IP for CCTV devices across all common ports
        /// </summary>
        private async Task ScanIpForCctvDevices(string ipAddress, Dictionary<int, string> ports, ConcurrentBag<ScanResult> results, CancellationToken cancellationToken)
        {
            var tasks = ports.Select(async port =>
            {
                var result = await ScanSinglePortAsync(ipAddress, port.Key, port.Value, cancellationToken);
                if (result.HasValue)
                    results.Add(result.Value);
            });

            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Scans a list of IP addresses for CCTV devices
        /// </summary>
        private async Task<List<ScanResult>> ScanIpListAsync(List<string> ipList, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var results = new ConcurrentBag<ScanResult>();
            var ports = portsToScan?.Any() == true ? portsToScan : _cctvPorts;
            var concurrencyLimit = Math.Min(20, ipList.Count);

            using var semaphore = new SemaphoreSlim(concurrencyLimit, concurrencyLimit);

            var tasks = ipList.Select(async ip =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    await ScanIpForCctvDevices(ip, ports, results, cancellationToken);
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);
            return results.ToList();
        }

        /// <summary>
        /// Scans a single port on a target for CCTV services and tests credentials
        /// </summary>
        private async Task<ScanResult?> ScanSinglePortAsync(string ipAddress, int port, string serviceName, CancellationToken cancellationToken)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                // First, check if port is open
                var isOpen = await IsPortOpenAsync(ipAddress, port, cancellationToken);
                if (!isOpen) return null;

                // Detect CCTV device
                var deviceInfo = await DetectCctvDeviceAsync(ipAddress, port, cancellationToken);
                if (deviceInfo == null) return null;

                // Test credentials
                var credentialResult = await TestCctvCredentialsAsync(ipAddress, port, deviceInfo.DeviceType, cancellationToken);

                var scanResult = new ScanResult(
                    ipAddress: IPAddress.Parse(ipAddress),
                    port: port,
                    isOpen: true,
                    service: serviceName,
                    pingTime: deviceInfo.ResponseTime,
                    operatingSystem: deviceInfo.OperatingSystem,
                    serverInfo: deviceInfo.ServerInfo,
                    discoveredAt: DateTime.UtcNow,
                    country: "",
                    hostname: await ResolveHostnameAsync(ipAddress),
                    isVulnerable: credentialResult?.IsVulnerable ?? false,
                    vulnerabilityInfo: credentialResult?.VulnerabilityDetails ?? "",
                    serviceName: deviceInfo.DeviceType
                );

                if (!TestEnvironmentDetector.IsTestEnvironment)
                {
                    var statusColor = credentialResult?.IsVulnerable == true ? "red" : "green";
                    var vulnText = credentialResult?.IsVulnerable == true ? " [red]🚨 VULNERABLE[/]" : " [green]✅ SECURE[/]";
                    AnsiConsole.MarkupLine($"[{statusColor}]📹 CCTV Device: {ipAddress}:{port} - {deviceInfo.DeviceType}{vulnText}[/]");
                }

                return scanResult;
            }
            catch (Exception)
            {
                return null;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <summary>
        /// Detects if a service is a CCTV device and identifies the type
        /// </summary>
        private async Task<CctvDeviceInfo?> DetectCctvDeviceAsync(string ipAddress, int port, CancellationToken cancellationToken)
        {
            try
            {
                var startTime = DateTime.UtcNow;
                var url = $"http://{ipAddress}:{port}";
                
                using var response = await _httpClient.GetAsync(url, cancellationToken);
                var responseTime = (DateTime.UtcNow - startTime).Milliseconds;
                
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                var headers = response.Headers.ToString();

                // Check for CCTV device indicators
                var deviceType = IdentifyDeviceType(content, headers);
                if (string.IsNullOrEmpty(deviceType)) return null;

                return new CctvDeviceInfo
                {
                    DeviceType = deviceType,
                    ResponseTime = responseTime,
                    ServerInfo = ExtractServerInfo(headers),
                    OperatingSystem = DetectOperatingSystem(headers, content)
                };
            }
            catch (HttpRequestException)
            {
                // Try HTTPS
                try
                {
                    var url = $"https://{ipAddress}:{port}";
                    using var response = await _httpClient.GetAsync(url, cancellationToken);
                    var content = await response.Content.ReadAsStringAsync(cancellationToken);
                    var headers = response.Headers.ToString();

                    var deviceType = IdentifyDeviceType(content, headers);
                    if (!string.IsNullOrEmpty(deviceType))
                    {
                        return new CctvDeviceInfo
                        {
                            DeviceType = deviceType,
                            ResponseTime = 0,
                            ServerInfo = ExtractServerInfo(headers),
                            OperatingSystem = DetectOperatingSystem(headers, content)
                        };
                    }
                }
                catch { }
            }
            catch { }

            return null;
        }

        /// <summary>
        /// Identifies CCTV device type based on HTTP response
        /// </summary>
        private string IdentifyDeviceType(string content, string headers)
        {
            var contentLower = content.ToLowerInvariant();
            var headersLower = headers.ToLowerInvariant();

            // Hikvision devices
            if (contentLower.Contains("hikvision") || headersLower.Contains("hikvision") ||
                contentLower.Contains("/doc/page/login.asp") || contentLower.Contains("dvr_login"))
                return "Hikvision DVR/Camera";

            // Dahua devices
            if (contentLower.Contains("dahua") || headersLower.Contains("dahua") ||
                contentLower.Contains("netkit") || contentLower.Contains("dvrip"))
                return "Dahua DVR/Camera";

            // Axis cameras
            if (contentLower.Contains("axis") || headersLower.Contains("axis") ||
                contentLower.Contains("axis communications"))
                return "Axis IP Camera";

            // Foscam cameras
            if (contentLower.Contains("foscam") || headersLower.Contains("foscam") ||
                contentLower.Contains("ipcam"))
                return "Foscam IP Camera";

            // Vivotek cameras
            if (contentLower.Contains("vivotek") || headersLower.Contains("vivotek"))
                return "Vivotek IP Camera";

            // Generic DVR indicators
            if (contentLower.Contains("digital video recorder") || contentLower.Contains("dvr") ||
                contentLower.Contains("surveillance") || contentLower.Contains("security camera") ||
                contentLower.Contains("network video recorder") || contentLower.Contains("nvr"))
                return "Generic DVR/NVR";

            // Generic IP camera indicators
            if (contentLower.Contains("ip camera") || contentLower.Contains("network camera") ||
                contentLower.Contains("webcam") || contentLower.Contains("mjpeg") ||
                contentLower.Contains("video stream"))
                return "Generic IP Camera";

            return "";
        }

        /// <summary>
        /// Tests default and common credentials for CCTV devices
        /// </summary>
        private async Task<CredentialTestResult?> TestCctvCredentialsAsync(string ipAddress, int port, string deviceType, CancellationToken cancellationToken)
        {
            var deviceKey = GetDeviceKey(deviceType);
            if (!DefaultCctvCredentials.TryGetValue(deviceKey, out var credentials))
            {
                // Try generic CCTV credentials
                DefaultCctvCredentials.TryGetValue("generic", out credentials);
            }

            if (credentials == null) return null;

            foreach (var credential in credentials.Take(10)) // Limit to prevent abuse
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    var isValid = await TestHttpBasicAuthAsync(ipAddress, port, credential.Username, credential.Password, cancellationToken);
                    if (isValid)
                    {
                        return new CredentialTestResult
                        {
                            IsVulnerable = true,
                            Username = credential.Username,
                            Password = credential.Password,
                            VulnerabilityDetails = $"Default credentials found: {credential.Username}:{credential.Password}. " +
                                                 "Recommendation: Change default credentials immediately and use strong passwords."
                        };
                    }
                }
                catch { }

                // Small delay to prevent overwhelming the device
                await Task.Delay(100, cancellationToken);
            }

            return new CredentialTestResult { IsVulnerable = false };
        }

        /// <summary>
        /// Tests HTTP Basic Authentication credentials
        /// </summary>
        private async Task<bool> TestHttpBasicAuthAsync(string ipAddress, int port, string username, string password, CancellationToken cancellationToken)
        {
            try
            {
                var authValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
                
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", authValue);

                var urls = new[] { $"http://{ipAddress}:{port}", $"http://{ipAddress}:{port}/", $"http://{ipAddress}:{port}/admin" };

                foreach (var url in urls)
                {
                    try
                    {
                        using var response = await client.GetAsync(url, cancellationToken);
                        if (response.IsSuccessStatusCode)
                            return true;
                    }
                    catch { }
                }
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Checks if a port is open
        /// </summary>
        private async Task<bool> IsPortOpenAsync(string ipAddress, int port, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);
                var timeoutTask = Task.Delay(2000, cancellationToken);

                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                return completedTask == connectTask && client.Connected;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Resolves hostname for an IP address
        /// </summary>
        private async Task<string> ResolveHostnameAsync(string ipAddress)
        {
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                return hostEntry.HostName;
            }
            catch
            {
                return ipAddress;
            }
        }

        /// <summary>
        /// Extracts server information from HTTP headers
        /// </summary>
        private string ExtractServerInfo(string headers)
        {
            var serverMatch = Regex.Match(headers, @"Server:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
            return serverMatch.Success ? serverMatch.Groups[1].Value.Trim() : "";
        }

        /// <summary>
        /// Detects operating system from headers and content
        /// </summary>
        private string DetectOperatingSystem(string headers, string content)
        {
            var combined = (headers + " " + content).ToLowerInvariant();

            if (combined.Contains("linux")) return "Linux";
            if (combined.Contains("windows")) return "Windows";
            if (combined.Contains("embedded")) return "Embedded";
            if (combined.Contains("rtems")) return "RTEMS";

            return "Unknown";
        }

        /// <summary>
        /// Gets device key for credential lookup
        /// </summary>
        private string GetDeviceKey(string deviceType)
        {
            var lower = deviceType.ToLowerInvariant();
            
            if (lower.Contains("hikvision")) return "hikvision";
            if (lower.Contains("dahua")) return "dahua";
            if (lower.Contains("axis")) return "axis";
            if (lower.Contains("foscam")) return "foscam";
            if (lower.Contains("vivotek")) return "vivotek";
            
            return "generic";
        }

        /// <summary>
        /// Initializes common CCTV ports
        /// </summary>
        private Dictionary<int, string> InitializeCctvPorts()
        {
            return new Dictionary<int, string>
            {
                { 80, "HTTP (Web Interface)" },
                { 443, "HTTPS (Secure Web Interface)" },
                { 554, "RTSP (Real Time Streaming Protocol)" },
                { 8080, "HTTP Alternate (Web Interface)" },
                { 8000, "HTTP (Hikvision/Dahua)" },
                { 37777, "TCP (Dahua DVR)" },
                { 34567, "TCP (Dahua DVR)" },
                { 1024, "TCP (Generic DVR)" },
                { 9000, "HTTP (Generic DVR)" },
                { 6036, "TCP (Generic DVR)" },
                { 10000, "TCP (Generic DVR)" }
            };
        }

        /// <summary>
        /// Initializes default CCTV credentials database
        /// </summary>
        private static Dictionary<string, List<DefaultCredential>> InitializeDefaultCredentials()
        {
            return new Dictionary<string, List<DefaultCredential>>
            {
                ["hikvision"] = new List<DefaultCredential>
                {
                    new("admin", "12345"),
                    new("admin", "admin"),
                    new("admin", "123456"),
                    new("admin", "password"),
                    new("admin", ""),
                    new("root", "12345"),
                    new("user", "user"),
                    new("guest", "guest")
                },
                ["dahua"] = new List<DefaultCredential>
                {
                    new("admin", "admin"),
                    new("admin", "123456"),
                    new("admin", ""),
                    new("admin", "password"),
                    new("root", "root"),
                    new("user", "user"),
                    new("guest", "guest"),
                    new("888888", "888888")
                },
                ["axis"] = new List<DefaultCredential>
                {
                    new("root", "pass"),
                    new("admin", "admin"),
                    new("user", "user"),
                    new("viewer", "viewer"),
                    new("admin", ""),
                    new("root", "root")
                },
                ["foscam"] = new List<DefaultCredential>
                {
                    new("admin", ""),
                    new("admin", "admin"),
                    new("admin", "123456"),
                    new("user", ""),
                    new("guest", "guest"),
                    new("operator", "operator")
                },
                ["vivotek"] = new List<DefaultCredential>
                {
                    new("root", ""),
                    new("admin", "admin"),
                    new("user", "user"),
                    new("guest", "guest")
                },
                ["generic"] = new List<DefaultCredential>
                {
                    new("admin", "admin"),
                    new("admin", ""),
                    new("admin", "123456"),
                    new("admin", "12345"),
                    new("admin", "password"),
                    new("admin", "1234"),
                    new("root", "root"),
                    new("root", ""),
                    new("root", "123456"),
                    new("user", "user"),
                    new("guest", "guest"),
                    new("viewer", "viewer"),
                    new("operator", "operator"),
                    new("service", "service"),
                    new("support", "support"),
                    new("tech", "tech"),
                    new("monitor", "monitor"),
                    new("demo", "demo"),
                    new("test", "test"),
                    new("camera", "camera"),
                    new("dvr", "dvr"),
                    new("nvr", "nvr"),
                    new("supervisor", "supervisor"),
                    new("security", "security")
                }
            };
        }

        /// <summary>
        /// Disposes of resources
        /// </summary>
        public void Dispose()
        {
            _semaphore?.Dispose();
            _httpClient?.Dispose();
        }

        /// <summary>
        /// Information about a detected CCTV device
        /// </summary>
        private class CctvDeviceInfo
        {
            public string DeviceType { get; set; } = "";
            public long ResponseTime { get; set; }
            public string ServerInfo { get; set; } = "";
            public string OperatingSystem { get; set; } = "";
        }

        /// <summary>
        /// Result of credential testing
        /// </summary>
        private class CredentialTestResult
        {
            public bool IsVulnerable { get; set; }
            public string Username { get; set; } = "";
            public string Password { get; set; } = "";
            public string VulnerabilityDetails { get; set; } = "";
        }

        /// <summary>
        /// Default credential entry
        /// </summary>
        private record DefaultCredential(string Username, string Password);
    }
}