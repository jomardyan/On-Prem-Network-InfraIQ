using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Constants;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Discovery.Core.Utilities;
using Discovery.Display;
using Spectre.Console;

namespace Discovery.Services.Scanning
{
    /// <summary>
    /// Scanner for IPv6 networks and addresses with enhanced discovery capabilities and comprehensive batch scanning
    /// </summary>
    public class IPv6Scanner : BaseBatchScanner, IScanner
    {
        private readonly int _timeout;
        private readonly int _maxConcurrency;

        public IPv6Scanner(int timeout = 2000, int maxConcurrency = 100)
        {
            _timeout = timeout;
            _maxConcurrency = maxConcurrency;
        }

        /// <summary>
        /// Scans a single IPv6 address for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanIPv6AddressAsync(string ipv6Address, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            if (!NetworkConstants.IsValidIPv6(ipv6Address))
            {
                throw new ArgumentException("Invalid IPv6 address format", nameof(ipv6Address));
            }

            var results = new ConcurrentBag<ScanResult>();
            LiveScanDisplay? liveDisplay = null;
            
            // Only use interactive display when not running in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment)
            {
                liveDisplay = new LiveScanDisplay(results);
                
                AnsiConsole.MarkupLine("[bold cyan]🔍 Starting IPv6 scan...[/]");
                AnsiConsole.MarkupLine($"[yellow]Target: {ipv6Address}[/]");
                AnsiConsole.MarkupLine($"[yellow]Scope: {NetworkConstants.GetIPv6Scope(ipv6Address)}[/]");
                AnsiConsole.MarkupLine($"[yellow]Ports: {portsToScan.Count}[/]");
                AnsiConsole.WriteLine();
                
                liveDisplay.StartLiveDisplay();
            }
            
            try
            {
                // Test IPv6 connectivity first
                var pingResult = await PingIPv6HostAsync(IPAddress.Parse(ipv6Address), _timeout);
                
                if (pingResult.Success)
                {
                    var os = NetworkConstants.GuessOperatingSystem(0);
                    await ScanIPv6PortsAsync(ipv6Address, results, portsToScan, pingResult.ResponseTime, os, cancellationToken);
                }
                else
                {
                    if (!TestEnvironmentDetector.IsTestEnvironment)
                    {
                        AnsiConsole.MarkupLine($"[yellow]IPv6 host {ipv6Address} appears to be offline or not responding.[/]");
                    }
                }
            }
            finally
            {
                if (liveDisplay != null)
                {
                    liveDisplay.StopLiveDisplay();
                    liveDisplay.Dispose();
                }
            }
            
            return results.ToList();
        }

        /// <summary>
        /// Discovers IPv6 hosts on the local network using various techniques
        /// </summary>
        public async Task<List<string>> DiscoverIPv6HostsAsync(CancellationToken cancellationToken)
        {
            var discoveredHosts = new ConcurrentBag<string>();
            
            AnsiConsole.MarkupLine("[bold cyan]🔍 Discovering IPv6 hosts on local network...[/]");
            AnsiConsole.WriteLine();

            var tasks = new List<Task>
            {
                // Neighbor Discovery Protocol (NDP) based discovery
                DiscoverViaNeighborTableAsync(discoveredHosts, cancellationToken),
                
                // Multicast ping discovery
                DiscoverViaMulticastPingAsync(discoveredHosts, cancellationToken),
                
                // Router Advertisement parsing
                DiscoverViaRouterAdvertisementAsync(discoveredHosts, cancellationToken),
                
                // Link-local range scan
                ScanLinkLocalRangeAsync(discoveredHosts, cancellationToken)
            };

            await Task.WhenAll(tasks);
            
            var uniqueHosts = discoveredHosts.Distinct().ToList();
            
            AnsiConsole.MarkupLine($"[green]✅ Discovered {uniqueHosts.Count} IPv6 hosts[/]");
            foreach (var host in uniqueHosts.Take(10)) // Show first 10
            {
                var scope = NetworkConstants.GetIPv6Scope(host);
                AnsiConsole.MarkupLine($"  [cyan]{host}[/] ([gray]{scope}[/])");
            }
            
            if (uniqueHosts.Count > 10)
            {
                AnsiConsole.MarkupLine($"  [gray]... and {uniqueHosts.Count - 10} more hosts[/]");
            }
            
            return uniqueHosts;
        }

        /// <summary>
        /// Scans IPv6 network prefix for active hosts
        /// </summary>
        public async Task<List<string>> ScanIPv6NetworkAsync(string networkPrefix, int prefixLength, CancellationToken cancellationToken)
        {
            if (!NetworkConstants.IsValidIPv6(networkPrefix))
            {
                throw new ArgumentException("Invalid IPv6 network prefix", nameof(networkPrefix));
            }

            if (prefixLength < 64 || prefixLength > 128)
            {
                throw new ArgumentException("IPv6 prefix length must be between 64 and 128", nameof(prefixLength));
            }

            var discoveredHosts = new ConcurrentBag<string>();
            var baseAddr = IPAddress.Parse(networkPrefix);
            var baseBytes = baseAddr.GetAddressBytes();
            
            // Calculate the number of host bits
            var hostBits = 128 - prefixLength;
            var maxHosts = Math.Min(Math.Pow(2, hostBits), 65536); // Limit to reasonable number
            
            AnsiConsole.MarkupLine($"[bold cyan]🔍 Scanning IPv6 network {networkPrefix}/{prefixLength}...[/]");
            AnsiConsole.MarkupLine($"[yellow]Maximum hosts to scan: {maxHosts:N0}[/]");
            
            if (maxHosts > 1000)
            {
                if (!AnsiConsole.Confirm($"[yellow]Warning: This will scan up to {maxHosts:N0} hosts. Continue?[/]"))
                {
                    return discoveredHosts.ToList();
                }
            }

            var semaphore = new SemaphoreSlim(_maxConcurrency);
            var tasks = new List<Task>();
            var scannedCount = 0;

            // Generate target addresses (simplified approach for demonstration)
            for (int i = 0; i < Math.Min(maxHosts, 1000); i++)
            {
                if (cancellationToken.IsCancellationRequested) break;

                var targetBytes = (byte[])baseBytes.Clone();
                
                // Modify the last few bytes to create different host addresses
                targetBytes[15] = (byte)(i & 0xFF);
                if (i > 255)
                {
                    targetBytes[14] = (byte)((i >> 8) & 0xFF);
                }
                if (i > 65535)
                {
                    targetBytes[13] = (byte)((i >> 16) & 0xFF);
                }

                var targetAddr = new IPAddress(targetBytes);
                var targetStr = targetAddr.ToString();

                await semaphore.WaitAsync(cancellationToken);
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var pingResult = await PingIPv6HostAsync(targetAddr, _timeout / 2);
                        if (pingResult.Success)
                        {
                            discoveredHosts.Add(targetStr);
                        }
                        Interlocked.Increment(ref scannedCount);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken));
            }

            await Task.WhenAll(tasks);
            
            var hosts = discoveredHosts.ToList();
            AnsiConsole.MarkupLine($"[green]✅ Found {hosts.Count} active IPv6 hosts out of {scannedCount} scanned[/]");
            
            return hosts;
        }

        #region IScanner Interface Implementation

        /// <summary>
        /// Scans a single IP address for open ports (adapter for ScanIPv6AddressAsync)
        /// </summary>
        public async Task<List<ScanResult>> ScanSingleIpAsync(string ipAddress, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            // Check if it's IPv6, if not, return empty results as this scanner is IPv6 specific
            if (!NetworkConstants.IsValidIPv6(ipAddress))
            {
                // Try to convert IPv4 to IPv6 mapped address
                if (IPAddress.TryParse(ipAddress, out var ipv4Addr) && ipv4Addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    var ipv6Mapped = ipv4Addr.MapToIPv6();
                    return await ScanIPv6AddressAsync(ipv6Mapped.ToString(), portsToScan, cancellationToken);
                }
                return new List<ScanResult>();
            }

            return await ScanIPv6AddressAsync(ipAddress, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans a range of IP addresses for open ports (converts to IPv6 mapped addresses)
        /// </summary>
        public async Task<List<ScanResult>> ScanNetworkRangeAsync(string baseIp, int startRange, int endRange, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var allResults = new List<ScanResult>();

            if (startRange > endRange || startRange < 1 || endRange > 254)
            {
                throw new ArgumentException("Invalid IP range specified");
            }

            var ipParts = baseIp.Split('.');
            if (ipParts.Length != 4)
            {
                throw new ArgumentException("Invalid base IP address format");
            }

            // Convert IPv4 range to IPv6 mapped addresses
            using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
            var tasks = new List<Task<List<ScanResult>>>();

            for (int i = startRange; i <= endRange; i++)
            {
                var targetIp = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.{i}";
                
                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        return await ScanSingleIpAsync(targetIp, portsToScan, cancellationToken);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);
            foreach (var result in results)
            {
                allResults.AddRange(result);
            }

            return allResults;
        }

        /// <summary>
        /// Scans a CIDR network for open ports (converts IPv4 CIDR to IPv6 mapped)
        /// </summary>
        public async Task<List<ScanResult>> ScanCidrNetworkAsync(IPAddress networkAddress, int subnetMask, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var allResults = new List<ScanResult>();

            if (subnetMask < 0 || subnetMask > 32)
            {
                throw new ArgumentException("Invalid subnet mask");
            }

            // Convert IPv4 CIDR to individual IPs and then to IPv6 mapped
            var hostBits = 32 - subnetMask;
            var hostCount = (int)Math.Pow(2, hostBits);
            
            var start = subnetMask >= 24 ? 1 : 0;
            var end = subnetMask >= 24 ? hostCount - 1 : hostCount;

            var networkBytes = networkAddress.GetAddressBytes();
            var networkLong = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0);

            using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
            var tasks = new List<Task<List<ScanResult>>>();

            for (var i = start; i < end; i++)
            {
                var hostLong = networkLong + (uint)i;
                var hostBytes = BitConverter.GetBytes(hostLong).Reverse().ToArray();
                var hostAddress = new IPAddress(hostBytes);
                var targetIp = hostAddress.ToString();

                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        return await ScanSingleIpAsync(targetIp, portsToScan, cancellationToken);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);
            foreach (var result in results)
            {
                allResults.AddRange(result);
            }

            return allResults;
        }

        /// <summary>
        /// Scans a CIDR network using string notation for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanCidrNetworkAsync(string cidrNotation, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            if (!TryParseCidr(cidrNotation, out var networkAddress, out var subnetMask) || networkAddress == null)
            {
                throw new ArgumentException("Invalid CIDR notation", nameof(cidrNotation));
            }

            return await ScanCidrNetworkAsync(networkAddress, subnetMask, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans a range of public IP addresses for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanPublicIpRangeAsync(IPAddress startIp, IPAddress endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var allResults = new List<ScanResult>();

            var startBytes = startIp.GetAddressBytes();
            var endBytes = endIp.GetAddressBytes();
            
            var startLong = BitConverter.ToUInt32(startBytes.Reverse().ToArray(), 0);
            var endLong = BitConverter.ToUInt32(endBytes.Reverse().ToArray(), 0);

            if (startLong > endLong)
            {
                throw new ArgumentException("Start IP must be less than or equal to end IP");
            }

            using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
            var tasks = new List<Task<List<ScanResult>>>();

            for (var i = startLong; i <= endLong; i++)
            {
                var hostBytes = BitConverter.GetBytes(i).Reverse().ToArray();
                var hostAddress = new IPAddress(hostBytes);
                var targetIp = hostAddress.ToString();

                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        return await ScanSingleIpAsync(targetIp, portsToScan, cancellationToken);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);
            foreach (var result in results)
            {
                allResults.AddRange(result);
            }

            return allResults;
        }

        /// <summary>
        /// Scans a range of IP addresses using string notation for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanIpRangeAsync(string startIp, string endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            if (!IPAddress.TryParse(startIp, out var startAddress))
            {
                throw new ArgumentException("Invalid start IP address", nameof(startIp));
            }

            if (!IPAddress.TryParse(endIp, out var endAddress))
            {
                throw new ArgumentException("Invalid end IP address", nameof(endIp));
            }

            return await ScanPublicIpRangeAsync(startAddress, endAddress, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans multiple targets from a CSV list containing IP addresses, CIDR networks, and IP ranges
        /// </summary>
        public async Task<List<ScanResult>> ScanCsvTargetsAsync(string csvContent, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var targets = ParseCsvTargets(csvContent);
            return await ScanBatchTargetsAsync(targets, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans multiple targets from a list of target strings (IPs, CIDRs, ranges)
        /// </summary>
        public async Task<List<ScanResult>> ScanBatchTargetsAsync(IEnumerable<string> targets, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            return await ProcessBatchScanAsync(targets, portsToScan, cancellationToken, ScanSingleIpAsync);
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Discovers hosts via neighbor table inspection
        /// </summary>
        private async Task DiscoverViaNeighborTableAsync(ConcurrentBag<string> hosts, CancellationToken cancellationToken)
        {
            try
            {
                // This would typically involve parsing the neighbor table
                // For cross-platform compatibility, we'll use network interface enumeration
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                
                foreach (var ni in networkInterfaces)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    
                    var properties = ni.GetIPProperties();
                    foreach (var addr in properties.UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
                            !addr.Address.Equals(IPAddress.IPv6Loopback))
                        {
                            hosts.Add(addr.Address.ToString());
                        }
                    }
                }
                
                await Task.Delay(100, cancellationToken); // Simulate async operation
            }
            catch
            {
                // Failed to enumerate neighbor table
            }
        }

        /// <summary>
        /// Discovers hosts via multicast ping (ICMPv6)
        /// </summary>
        private async Task DiscoverViaMulticastPingAsync(ConcurrentBag<string> hosts, CancellationToken cancellationToken)
        {
            try
            {
                // Well-known IPv6 multicast addresses
                var multicastAddresses = new[]
                {
                    "ff02::1", // All nodes link-local multicast
                    "ff02::2", // All routers link-local multicast
                    "ff02::1:ff00:0" // Solicited-node multicast
                };

                foreach (var multicastAddr in multicastAddresses)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    
                    try
                    {
                        using var ping = new Ping();
                        var reply = await ping.SendPingAsync(IPAddress.Parse(multicastAddr), _timeout);
                        
                        // Note: This is simplified - in reality, you'd capture ICMPv6 responses
                        // from multiple hosts responding to the multicast ping
                    }
                    catch
                    {
                        // Ping failed or not supported
                    }
                }
            }
            catch
            {
                // Multicast ping discovery failed
            }
        }

        /// <summary>
        /// Discovers hosts via Router Advertisement monitoring
        /// </summary>
        private async Task DiscoverViaRouterAdvertisementAsync(ConcurrentBag<string> hosts, CancellationToken cancellationToken)
        {
            try
            {
                // This would typically involve listening for Router Advertisement messages
                // For now, we'll simulate by checking for common router addresses
                var commonRouterSuffixes = new[] { "::1", "::254", "::fe" };
                
                var localAddresses = NetworkConstants.GetLocalIPv6Addresses();
                
                foreach (var localAddr in localAddresses)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    
                    if (NetworkConstants.IsIPv6LinkLocal(localAddr))
                    {
                        // Extract network prefix and try common router addresses
                        var addr = IPAddress.Parse(localAddr);
                        var bytes = addr.GetAddressBytes();
                        
                        foreach (var suffix in commonRouterSuffixes)
                        {
                            try
                            {
                                // Build potential router address
                                var routerBytes = (byte[])bytes.Clone();
                                var suffixAddr = IPAddress.Parse(suffix);
                                var suffixBytes = suffixAddr.GetAddressBytes();
                                
                                // Copy suffix into the last 8 bytes (interface identifier)
                                Array.Copy(suffixBytes, 8, routerBytes, 8, 8);
                                
                                var routerAddr = new IPAddress(routerBytes);
                                var pingResult = await PingIPv6HostAsync(routerAddr, _timeout);
                                
                                if (pingResult.Success)
                                {
                                    hosts.Add(routerAddr.ToString());
                                }
                            }
                            catch
                            {
                                // Failed to construct or ping router address
                            }
                        }
                    }
                }
            }
            catch
            {
                // Router advertisement discovery failed
            }
        }

        /// <summary>
        /// Scans link-local address range for active hosts
        /// </summary>
        private async Task ScanLinkLocalRangeAsync(ConcurrentBag<string> hosts, CancellationToken cancellationToken)
        {
            try
            {
                // Scan some common link-local addresses
                var linkLocalBase = "fe80::";
                var commonSuffixes = new[]
                {
                    "1", "2", "3", "4", "5", "a", "b", "c", "d", "e", "f",
                    "10", "20", "100", "200", "254", "fe", "ff"
                };

                var tasks = commonSuffixes.Select(async suffix =>
                {
                    try
                    {
                        var testAddr = $"{linkLocalBase}{suffix}";
                        if (NetworkConstants.IsValidIPv6(testAddr))
                        {
                            var pingResult = await PingIPv6HostAsync(IPAddress.Parse(testAddr), _timeout);
                            if (pingResult.Success)
                            {
                                hosts.Add(testAddr);
                            }
                        }
                    }
                    catch
                    {
                        // Failed to ping this address
                    }
                });

                await Task.WhenAll(tasks);
            }
            catch
            {
                // Link-local scanning failed
            }
        }

        /// <summary>
        /// Pings an IPv6 host to test connectivity
        /// </summary>
        private async Task<(bool Success, long ResponseTime)> PingIPv6HostAsync(IPAddress ipv6Address, int timeout)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipv6Address, timeout);
                
                if (reply.Status == IPStatus.Success)
                {
                    return (true, reply.RoundtripTime);
                }
            }
            catch
            {
                // Ping failed - try TCP connectivity test as fallback
                return await TcpConnectivityTestIPv6(ipv6Address, timeout);
            }
            
            return (false, 0);
        }

        /// <summary>
        /// Tests IPv6 TCP connectivity as a fallback for ping
        /// </summary>
        private async Task<(bool Success, long ResponseTime)> TcpConnectivityTestIPv6(IPAddress ipv6Address, int timeout)
        {
            var commonPorts = new[] { 80, 443, 22, 21, 23, 25, 53 };
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            var tasks = commonPorts.Select(port => TestTcpConnectionIPv6(ipv6Address, port, timeout / commonPorts.Length));
            
            try
            {
                var completedTask = await Task.WhenAny(tasks);
                stopwatch.Stop();
                
                if (await completedTask)
                {
                    return (true, stopwatch.ElapsedMilliseconds);
                }
            }
            catch
            {
                // All connections failed
            }
            finally
            {
                stopwatch.Stop();
            }
            
            return (false, 0);
        }

        /// <summary>
        /// Tests TCP connection to a specific IPv6 address and port
        /// </summary>
        private async Task<bool> TestTcpConnectionIPv6(IPAddress ipv6Address, int port, int timeout)
        {
            try
            {
                using var client = new TcpClient(AddressFamily.InterNetworkV6);
                var connectTask = client.ConnectAsync(ipv6Address, port);
                if (await Task.WhenAny(connectTask, Task.Delay(timeout)) == connectTask)
                {
                    return client.Connected;
                }
            }
            catch
            {
                // Connection failed
            }
            return false;
        }

        /// <summary>
        /// Scans IPv6 ports on a specific host
        /// </summary>
        private async Task ScanIPv6PortsAsync(string ipv6Address, ConcurrentBag<ScanResult> results, Dictionary<int, string> portsToScan, long pingTime, string operatingSystem, CancellationToken token)
        {
            var semaphore = new SemaphoreSlim(_maxConcurrency);
            var tasks = portsToScan.Select(async portEntry =>
            {
                await semaphore.WaitAsync(token);
                try
                {
                    if (token.IsCancellationRequested) return;

                    using var client = new TcpClient(AddressFamily.InterNetworkV6);
                    try
                    {
                        var connectTask = client.ConnectAsync(IPAddress.Parse(ipv6Address), portEntry.Key);
                        if (await Task.WhenAny(connectTask, Task.Delay(_timeout, token)) == connectTask)
                        {
                            await connectTask;
                            
                            var serverInfo = $"IPv6/{NetworkConstants.GetIPv6Scope(ipv6Address)}";
                            var isVulnerable = NetworkConstants.IsPortVulnerable(portEntry.Key);
                            var vulnInfo = isVulnerable ? NetworkConstants.GetPortVulnerabilityInfo(portEntry.Key) : "";
                            
                            // Perform reverse DNS lookup
                            var hostname = await DnsLookupHelper.GetHostnameAsync(ipv6Address, 2000);
                            
                            var scanResult = new ScanResult(
                                IPAddress.Parse(ipv6Address),
                                portEntry.Key,
                                true,
                                portEntry.Value,
                                pingTime,
                                operatingSystem,
                                serverInfo,
                                DateTime.UtcNow,
                                "",
                                hostname,
                                isVulnerable,
                                vulnInfo,
                                portEntry.Value
                            );
                            
                            results.Add(scanResult);
                        }
                    }
                    catch (SocketException)
                    {
                        // Port is closed
                    }
                    catch (OperationCanceledException)
                    {
                        // Scan was cancelled
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });
            
            await Task.WhenAll(tasks);
        }

        #endregion
    }
}