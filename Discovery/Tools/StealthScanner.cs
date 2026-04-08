using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core;
using Discovery.Core.Configuration;
using Discovery.Core.Models;
using Discovery.Core.Utilities;

namespace Discovery.Tools
{
    /// <summary>
    /// Stealth scanning implementation with anti-detection features
    /// </summary>
    public static class StealthScanner
    {
        private static readonly Random _random = new();

        /// <summary>
        /// Performs a stealth port scan with anti-detection techniques
        /// </summary>
        public static async Task<bool> StealthPortScanAsync(
            IPAddress target, 
            int port, 
            StealthConfig config, 
            CancellationToken cancellationToken = default)
        {
            // Apply random delay before scanning
            if (config.MinScanDelay > 0)
            {
                var delay = config.GetRandomDelay();
                await Task.Delay(delay, cancellationToken);
            }

            try
            {
                using var client = new TcpClient();
                
                // Configure source port if randomization is enabled
                if (config.RandomizeSourcePorts)
                {
                    var sourcePort = config.GetRandomSourcePort();
                    var localEndPoint = new IPEndPoint(IPAddress.Any, sourcePort);
                    client.Client.Bind(localEndPoint);
                }

                // Configure socket options for stealth
                client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                client.ReceiveTimeout = config.ConnectionTimeout;
                client.SendTimeout = config.ConnectionTimeout;

                var connectTask = client.ConnectAsync(target, port);
                var timeoutTask = Task.Delay(config.ConnectionTimeout, cancellationToken);

                var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                if (completedTask == connectTask && !connectTask.IsFaulted && client.Connected)
                {
                    // Port is open - apply additional stealth measures
                    await ApplyConnectionStealth(client, config);
                    return true;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // Port is closed or connection failed
            }

            return false;
        }

        /// <summary>
        /// Applies stealth techniques during an active connection
        /// </summary>
        private static async Task ApplyConnectionStealth(TcpClient client, StealthConfig config)
        {
            try
            {
                // Brief connection to avoid triggering IDS rules
                var stream = client.GetStream();
                
                // Send minimal data if needed for protocol detection
                // This mimics legitimate connection behavior
                if (stream.CanWrite)
                {
                    await Task.Delay(10); // Brief delay
                }

                // Quick graceful disconnect
                client.Close();
            }
            catch
            {
                // Ignore errors during stealth operations
            }
        }

        /// <summary>
        /// Randomizes the order of ports to scan for better stealth
        /// </summary>
        public static IEnumerable<int> RandomizePortOrder(IEnumerable<int> ports, bool randomize = true)
        {
            var portList = ports.ToList();
            
            if (!randomize)
                return portList;

            // Fisher-Yates shuffle algorithm
            for (int i = portList.Count - 1; i > 0; i--)
            {
                int j = _random.Next(i + 1);
                (portList[i], portList[j]) = (portList[j], portList[i]);
            }

            return portList;
        }

        /// <summary>
        /// Randomizes the order of IP addresses to scan
        /// </summary>
        public static IEnumerable<IPAddress> RandomizeIpOrder(IEnumerable<IPAddress> addresses, bool randomize = true)
        {
            var addressList = addresses.ToList();
            
            if (!randomize)
                return addressList;

            // Fisher-Yates shuffle algorithm
            for (int i = addressList.Count - 1; i > 0; i--)
            {
                int j = _random.Next(i + 1);
                (addressList[i], addressList[j]) = (addressList[j], addressList[i]);
            }

            return addressList;
        }

        /// <summary>
        /// Creates adaptive delays based on network response patterns
        /// </summary>
        public static async Task AdaptiveDelay(TimeSpan lastResponseTime, StealthConfig config)
        {
            // If the last scan was very fast, it might indicate potential detection
            // Increase delay proportionally
            var baseDelay = config.GetRandomDelay();
            
            if (lastResponseTime.TotalMilliseconds < 10)
            {
                // Very fast response - increase stealth delay
                baseDelay = (int)(baseDelay * 1.5);
            }
            else if (lastResponseTime.TotalMilliseconds > 1000)
            {
                // Slow response - might be rate limiting, increase delay significantly
                baseDelay = (int)(baseDelay * 2.0);
            }

            await Task.Delay(Math.Min(baseDelay, 5000)); // Cap at 5 seconds
        }

        /// <summary>
        /// Implements decoy scanning by generating fake scan targets
        /// </summary>
        public static async Task<bool> DecoyPortScanAsync(
            IPAddress target,
            int port,
            IPAddress[] decoyIps,
            StealthConfig config,
            CancellationToken cancellationToken = default)
        {
            var tasks = new List<Task<bool>>();
            
            // Add the real scan
            tasks.Add(StealthPortScanAsync(target, port, config, cancellationToken));
            
            // Add decoy scans to mask the real scan
            foreach (var decoy in decoyIps.Take(3)) // Limit decoys to avoid too much traffic
            {
                tasks.Add(DecoyStealthScan(decoy, port, config, cancellationToken));
            }

            // Randomize execution order
            var randomizedTasks = tasks.OrderBy(t => _random.Next()).ToArray();
            
            var results = await Task.WhenAll(randomizedTasks);
            
            // Return the result of the first task (the real scan)
            return results[0];
        }

        /// <summary>
        /// Performs a decoy scan that doesn't report results
        /// </summary>
        private static async Task<bool> DecoyStealthScan(
            IPAddress target,
            int port,
            StealthConfig config,
            CancellationToken cancellationToken)
        {
            try
            {
                // Perform scan but don't care about the result
                await StealthPortScanAsync(target, port, config, cancellationToken);
                return false; // Always return false for decoys
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Implements timing-based evasion techniques
        /// </summary>
        public static class TimingEvasion
        {
            /// <summary>
            /// Calculates optimal scan timing to avoid rate limit detection
            /// </summary>
            public static TimeSpan CalculateOptimalTiming(int totalTargets, TimeSpan maxScanTime)
            {
                // Spread scans evenly over the time period with some randomization
                var baseInterval = maxScanTime.TotalMilliseconds / totalTargets;
                var randomFactor = _random.NextDouble() * 0.5 + 0.75; // 75% to 125% of base
                
                return TimeSpan.FromMilliseconds(baseInterval * randomFactor);
            }

            /// <summary>
            /// Implements exponential backoff for repeated scan attempts
            /// </summary>
            public static async Task ExponentialBackoff(int attemptNumber, int maxDelayMs = 8000)
            {
                var delay = Math.Min(100 * (int)Math.Pow(2, attemptNumber), maxDelayMs);
                var jitter = _random.Next(0, delay / 4); // Add up to 25% jitter
                
                await Task.Delay(delay + jitter);
            }
        }

        /// <summary>
        /// Generates realistic network traffic patterns to avoid detection
        /// </summary>
        public static class TrafficCamouflage
        {
            /// <summary>
            /// Simulates legitimate network browsing behavior
            /// </summary>
            public static async Task SimulateLegitimateTraffic(StealthConfig config)
            {
                try
                {
                    // Generate some HTTP requests to common sites to blend in
                    var commonSites = new[]
                    {
                        "http://www.google.com",
                        "http://www.microsoft.com",
                        "http://www.github.com"
                    };

                    var selectedSite = commonSites[_random.Next(commonSites.Length)];
                    
                    using var client = new System.Net.Http.HttpClient();
                    client.DefaultRequestHeaders.Add("User-Agent", config.GetRandomUserAgent());
                    client.Timeout = TimeSpan.FromSeconds(5);

                    try
                    {
                        var response = await client.GetAsync(selectedSite);
                        // Don't care about the response, just generate traffic
                    }
                    catch
                    {
                        // Ignore failures in camouflage traffic
                    }
                }
                catch
                {
                    // If camouflage fails, continue with regular scanning
                }
            }
        }

        // ===== BATCH SCANNING METHODS =====

        /// <summary>
        /// Performs stealth scanning from a CSV list containing IP addresses, CIDR networks, and IP ranges
        /// </summary>
        /// <param name="csvContent">CSV content with targets (IPs, CIDRs, ranges)</param>
        /// <param name="ports">Ports to scan</param>
        /// <param name="config">Stealth configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of stealth scan results</returns>
        public static async Task<List<ScanResult>> StealthScanFromCsvAsync(string csvContent, Dictionary<int, string> ports, StealthConfig config, CancellationToken cancellationToken = default)
        {
            var targets = ParseCsvTargets(csvContent);
            return await StealthBatchScanAsync(targets, ports, config, cancellationToken);
        }

        /// <summary>
        /// Performs stealth scanning in a CIDR network range
        /// </summary>
        /// <param name="cidrNotation">CIDR notation (e.g., 192.168.1.0/24)</param>
        /// <param name="ports">Ports to scan</param>
        /// <param name="config">Stealth configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of stealth scan results</returns>
        public static async Task<List<ScanResult>> StealthScanCidrAsync(string cidrNotation, Dictionary<int, string> ports, StealthConfig config, CancellationToken cancellationToken = default)
        {
            var targets = new[] { cidrNotation };
            return await StealthBatchScanAsync(targets, ports, config, cancellationToken);
        }

        /// <summary>
        /// Performs stealth scanning in an IP range
        /// </summary>
        /// <param name="startIp">Starting IP address</param>
        /// <param name="endIp">Ending IP address</param>
        /// <param name="ports">Ports to scan</param>
        /// <param name="config">Stealth configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of stealth scan results</returns>
        public static async Task<List<ScanResult>> StealthScanIpRangeAsync(string startIp, string endIp, Dictionary<int, string> ports, StealthConfig config, CancellationToken cancellationToken = default)
        {
            var rangeTarget = $"{startIp}-{endIp}";
            var targets = new[] { rangeTarget };
            return await StealthBatchScanAsync(targets, ports, config, cancellationToken);
        }

        /// <summary>
        /// Performs stealth scanning on multiple targets from a list of target strings (IPs, CIDRs, ranges)
        /// </summary>
        /// <param name="targets">Collection of target strings</param>
        /// <param name="ports">Ports to scan</param>
        /// <param name="config">Stealth configuration</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of stealth scan results</returns>
        public static async Task<List<ScanResult>> StealthBatchScanAsync(IEnumerable<string> targets, Dictionary<int, string> ports, StealthConfig config, CancellationToken cancellationToken = default)
        {
            var allResults = new List<ScanResult>();
            var expandedIps = ExpandTargetsToIps(targets).Distinct().ToList();
            
            // Skip interactive prompts in test environment
            if (!Discovery.Core.Utilities.TestEnvironmentDetector.IsTestEnvironment && expandedIps.Count > 50)
            {
                Console.WriteLine($"About to perform stealth scan on {expandedIps.Count} IP addresses. This may take a while due to stealth timing.");
                Console.Write("Continue? (y/N): ");
                var response = Console.ReadLine();
                if (!string.Equals(response?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Stealth scan cancelled by user.");
                    return allResults;
                }
            }

            Console.WriteLine($"👻 Starting batch stealth scan on {expandedIps.Count} targets with {ports.Count} ports each...");

            // Very low concurrency for stealth
            using var semaphore = new SemaphoreSlim(Math.Min(3, expandedIps.Count), Math.Min(3, expandedIps.Count));
            
            var tasks = expandedIps.Select(async ip =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (IPAddress.TryParse(ip, out var ipAddress))
                    {
                        var hostResults = new List<ScanResult>();
                        
                        foreach (var port in ports)
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            
                            var isOpen = await StealthPortScanAsync(ipAddress, port.Key, config, cancellationToken);
                            if (isOpen)
                            {
                                // Perform reverse DNS lookup with longer timeout for stealth
                                var hostname = await DnsLookupHelper.GetHostnameAsync(ipAddress, 3000);
                                
                                hostResults.Add(new ScanResult(
                                    ipAddress,
                                    port.Key,
                                    true,
                                    port.Value,
                                    0, // No ping time in stealth mode
                                    "Unknown", // No OS detection in stealth mode
                                    "",
                                    DateTime.UtcNow,
                                    "",
                                    hostname
                                ));
                            }
                            
                            // Additional stealth delay between ports
                            if (config.MinScanDelay > 0)
                            {
                                var delay = config.GetRandomDelay();
                                await Task.Delay(delay, cancellationToken);
                            }
                        }
                        
                        return hostResults;
                    }
                    return new List<ScanResult>();
                }
                catch (Exception ex)
                {
                    // Log error but continue with other IPs
                    if (!Discovery.Core.Utilities.TestEnvironmentDetector.IsTestEnvironment)
                        Console.WriteLine($"Error in stealth scan of {ip}: {ex.Message}");
                    return new List<ScanResult>();
                }
                finally
                {
                    semaphore.Release();
                }
            });

            var results = await Task.WhenAll(tasks);
            
            foreach (var result in results)
            {
                allResults.AddRange(result);
            }
            
            if (!Discovery.Core.Utilities.TestEnvironmentDetector.IsTestEnvironment)
            {
                Console.WriteLine($"✅ Stealth scan completed: {allResults.Count} open ports found across {expandedIps.Count} targets");
            }

            return allResults;
        }

        // ===== HELPER METHODS FOR BATCH SCANNING =====

        private static IEnumerable<string> ParseCsvTargets(string csvContent)
        {
            if (string.IsNullOrWhiteSpace(csvContent))
                yield break;

            var lines = csvContent.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#") || trimmedLine.StartsWith("//"))
                    continue;

                var targets = trimmedLine.Split(new[] { ',', ';', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                
                foreach (var target in targets)
                {
                    var cleanTarget = target.Trim();
                    if (!string.IsNullOrEmpty(cleanTarget))
                        yield return cleanTarget;
                }
            }
        }

        private static IEnumerable<string> ExpandTargetsToIps(IEnumerable<string> targets)
        {
            foreach (var target in targets)
            {
                foreach (var ip in ExpandSingleTargetToIps(target))
                {
                    yield return ip;
                }
            }
        }

        private static IEnumerable<string> ExpandSingleTargetToIps(string target)
        {
            if (string.IsNullOrWhiteSpace(target))
                yield break;

            target = target.Trim();

            if (target.Contains('/'))
            {
                foreach (var ip in ExpandCidrToIps(target))
                    yield return ip;
            }
            else if (target.Contains('-'))
            {
                foreach (var ip in ExpandRangeToIps(target))
                    yield return ip;
            }
            else if (IPAddress.TryParse(target, out _))
            {
                yield return target;
            }
        }

        private static IEnumerable<string> ExpandCidrToIps(string cidr)
        {
            if (!TryParseCidr(cidr, out var networkAddress, out var subnetMask))
                yield break;

            if (networkAddress == null)
                yield break;

            var hostBits = 32 - subnetMask;
            var hostCount = (int)Math.Pow(2, hostBits);
            
            var start = subnetMask >= 24 ? 1 : 0;
            var end = subnetMask >= 24 ? hostCount - 1 : hostCount;

            var networkBytes = networkAddress.GetAddressBytes();
            var networkLong = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0);

            for (var i = start; i < end; i++)
            {
                var hostLong = networkLong + (uint)i;
                var hostBytes = BitConverter.GetBytes(hostLong).Reverse().ToArray();
                var hostAddress = new IPAddress(hostBytes);
                yield return hostAddress.ToString();
            }
        }

        private static IEnumerable<string> ExpandRangeToIps(string range)
        {
            var parts = range.Split('-');
            if (parts.Length != 2)
                yield break;

            var startIp = parts[0].Trim();
            var endPart = parts[1].Trim();

            if (!IPAddress.TryParse(startIp, out var startAddress))
                yield break;

            if (IPAddress.TryParse(endPart, out var endAddress))
            {
                foreach (var ip in GetIpRange(startAddress, endAddress))
                    yield return ip;
            }
            else if (int.TryParse(endPart, out var endOctet) && endOctet >= 0 && endOctet <= 255)
            {
                var startBytes = startAddress.GetAddressBytes();
                startBytes[3] = (byte)endOctet;
                var endIpAddress = new IPAddress(startBytes);
                
                foreach (var ip in GetIpRange(startAddress, endIpAddress))
                    yield return ip;
            }
        }

        private static IEnumerable<string> GetIpRange(IPAddress startIp, IPAddress endIp)
        {
            var startBytes = startIp.GetAddressBytes();
            var endBytes = endIp.GetAddressBytes();
            
            var startLong = BitConverter.ToUInt32(startBytes.Reverse().ToArray(), 0);
            var endLong = BitConverter.ToUInt32(endBytes.Reverse().ToArray(), 0);

            for (var i = startLong; i <= endLong; i++)
            {
                var hostBytes = BitConverter.GetBytes(i).Reverse().ToArray();
                var hostAddress = new IPAddress(hostBytes);
                yield return hostAddress.ToString();
            }
        }

        private static bool TryParseCidr(string cidr, out IPAddress? networkAddress, out int subnetMask)
        {
            networkAddress = null;
            subnetMask = 0;
            
            if (string.IsNullOrWhiteSpace(cidr))
                return false;
                
            var parts = cidr.Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out networkAddress) || !int.TryParse(parts[1], out subnetMask))
                return false;
                
            if (subnetMask < 0 || subnetMask > 32)
                return false;
                
            return true;
        }
    }
}