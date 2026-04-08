using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;
using Discovery.Core.Constants;
using Discovery.Core.Models;
using Discovery.Core.Utilities;
using Discovery.Services.Utilities;

namespace Discovery.Tools
{
    public static class NetworkScanner
    {
        public static async Task<List<ScanResult>> PerformCidrScan(IPAddress networkAddress, int subnetMask, 
            Dictionary<int, string> portsToScan, CancellationTokenSource cts)
        {
            var results = new ConcurrentBag<ScanResult>();
            var networkBytes = networkAddress.GetAddressBytes();
            uint network = (uint)networkBytes[0] << 24 | (uint)networkBytes[1] << 16 | (uint)networkBytes[2] << 8 | networkBytes[3];
            
            uint mask = 0xFFFFFFFF << (32 - subnetMask);
            network = network & mask;
            
            uint hostBits = (uint)(32 - subnetMask);
            uint totalHosts = (uint)(Math.Pow(2, hostBits) - 2);
            
            if (totalHosts > 65536)
            {
                if (!AnsiConsole.Confirm($"[yellow]⚠️ Warning: You are about to scan {totalHosts} IP addresses. This could take a very long time. Are you sure?[/]"))
                {
                    return results.ToList();
                }
            }

            var liveDisplay = new Display.LiveScanDisplay(results, (int)totalHosts);
            
            AnsiConsole.MarkupLine("[bold cyan]🔍 Starting CIDR network scan with live results...[/]");
            AnsiConsole.MarkupLine($"[yellow]🌐 Network: {networkAddress}/{subnetMask} ({totalHosts} hosts)[/]");
            AnsiConsole.MarkupLine($"[yellow]🔌 Ports per host: {portsToScan.Count}[/]");
            AnsiConsole.WriteLine();
            
            liveDisplay.StartLiveDisplay();

            try
            {
                await AnsiConsole.Progress()
                    .Columns(new ProgressColumn[]
                    {
                        new TaskDescriptionColumn(),
                        new ProgressBarColumn(),
                        new PercentageColumn(),
                        new RemainingTimeColumn(),
                        new SpinnerColumn(),
                    })
                    .StartAsync(async ctx =>
                    {
                        var scanTask = ctx.AddTask("[green]🔍 Scanning CIDR network[/]");
                        scanTask.MaxValue = totalHosts;
                        var tasks = new List<Task>();
                        var semaphore = new SemaphoreSlim(200);

                        for (uint i = 1; i <= totalHosts; i++)
                        {
                            if (cts.IsCancellationRequested) break;

                            uint currentIp = network + i;
                            var currentIpBytes = new byte[4];
                            currentIpBytes[0] = (byte)(currentIp >> 24);
                            currentIpBytes[1] = (byte)(currentIp >> 16);
                            currentIpBytes[2] = (byte)(currentIp >> 8);
                            currentIpBytes[3] = (byte)currentIp;
                            var ipToScan = new IPAddress(currentIpBytes).ToString();

                            await semaphore.WaitAsync(cts.Token);
                            tasks.Add(Task.Run(async () =>
                            {
                                try
                                {
                                    await PingAndScanPorts(ipToScan, results, portsToScan, cts.Token);
                                }
                                finally
                                {
                                    scanTask.Increment(1);
                                    semaphore.Release();
                                }
                            }, cts.Token));
                        }
                        await Task.WhenAll(tasks);
                    });
            }
            finally
            {
                liveDisplay.StopLiveDisplay();
                liveDisplay.Dispose();
            }
            
            return results.ToList();
        }

        public static async Task<List<ScanResult>> PerformScan(string baseIp, int start, int end, 
            Dictionary<int, string> portsToScan, CancellationTokenSource cts)
        {
            var results = new ConcurrentBag<ScanResult>();
            var liveDisplay = new Display.LiveScanDisplay(results);
            
            AnsiConsole.MarkupLine("[bold cyan]🔍 Starting network scan with live results...[/]");
            AnsiConsole.MarkupLine($"[yellow]🌐 Scanning range: {baseIp}{start}-{end} ({end - start + 1} IPs)[/]");
            AnsiConsole.MarkupLine($"[yellow]🔌 Ports per host: {portsToScan.Count}[/]");
            AnsiConsole.WriteLine();
            
            liveDisplay.StartLiveDisplay();
            
            try
            {
                await AnsiConsole.Progress()
                    .Columns(new ProgressColumn[]
                    {
                        new TaskDescriptionColumn(),
                        new ProgressBarColumn(),
                        new PercentageColumn(),
                        new RemainingTimeColumn(),
                        new SpinnerColumn(),
                    })
                    .StartAsync(async ctx =>
                    {
                        var scanTask = ctx.AddTask("[green]🔍 Scanning network[/]");
                        var tasks = new List<Task>();
                        var semaphore = new SemaphoreSlim(100);

                        for (int i = start; i <= end; i++)
                        {
                            if (cts.IsCancellationRequested) break;
                            string ipToScan = baseIp + i;
                            await semaphore.WaitAsync(cts.Token);
                            tasks.Add(Task.Run(async () =>
                            {
                                try
                                {
                                    await PingAndScanPorts(ipToScan, results, portsToScan, cts.Token);
                                }
                                finally
                                {
                                    scanTask.Increment(100.0 / (end - start + 1));
                                    semaphore.Release();
                                }
                            }, cts.Token));
                        }
                        await Task.WhenAll(tasks);
                    });
            }
            finally
            {
                liveDisplay.StopLiveDisplay();
                liveDisplay.Dispose();
            }
            
            return results.ToList();
        }

        public static async Task PingAndScanPorts(string ipAddress, ConcurrentBag<ScanResult> results, 
            Dictionary<int, string> portsToScan, CancellationToken token)
        {
            try
            {
                if (!IPAddress.TryParse(ipAddress, out var ip))
                    return;

                // Add timeout to ping operation to prevent hanging
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(5)); // Max 5 seconds per host

                var pingResult = await PingHostAsync(ip, 1000);
                if (pingResult.Success)
                {
                    var os = NetworkConstants.GuessOperatingSystem(0); // TTL not available with TCP test
                    await ScanPorts(ipAddress, results, portsToScan, pingResult.ResponseTime, os, timeoutCts.Token);
                }
            }
            catch (OperationCanceledException)
            {
                // Scan was cancelled or timed out - this is expected
            }
            catch (Exception)
            {
                // Host is not reachable or other error - continue with next host
            }
        }

        public static async Task ScanPorts(string ipAddress, ConcurrentBag<ScanResult> results, 
            Dictionary<int, string> portsToScan, long pingTime, string operatingSystem, CancellationToken token)
        {
            // Use semaphore to limit concurrent port scans per host
            var semaphore = new SemaphoreSlim(20, 20); // Max 20 ports per host concurrently
            
            var tasks = portsToScan.Select(async portEntry =>
            {
                if (token.IsCancellationRequested) return;

                await semaphore.WaitAsync(token);
                try
                {
                    using var client = new TcpClient();
                    try
                    {
                        // Use shorter timeout and proper cancellation
                        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                        timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(2000)); // 2 second timeout per port
                        
                        var connectTask = client.ConnectAsync(ipAddress, portEntry.Key);
                        var delayTask = Task.Delay(2000, timeoutCts.Token);
                        
                        var completedTask = await Task.WhenAny(connectTask, delayTask);
                        
                        if (completedTask == connectTask && !connectTask.IsFaulted && client.Connected)
                        {
                            await connectTask; // Ensure the connection task completes
                            
                            var serverInfo = "";
                            var isVulnerable = NetworkConstants.VulnerablePorts.ContainsKey(portEntry.Key);
                            var vulnInfo = isVulnerable ? NetworkConstants.VulnerablePorts[portEntry.Key] : "";
                            
                            // Only get server info for HTTPS ports to avoid hanging
                            if (portEntry.Key == 443 || portEntry.Value == "HTTPS")
                            {
                                try
                                {
                                    using var serverInfoCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                                    serverInfoCts.CancelAfter(TimeSpan.FromMilliseconds(1000)); // 1 second max for server info
                                    serverInfo = await GetHttpsServerInfo(ipAddress, portEntry.Key, serverInfoCts.Token);
                                }
                                catch
                                {
                                    // Ignore server info errors
                                    serverInfo = "";
                                }
                            }
                            
                            var result = new Discovery.Core.Models.ScanResult(
                                IPAddress.Parse(ipAddress),
                                portEntry.Key,
                                true,
                                portEntry.Value,
                                pingTime,
                                operatingSystem,
                                serverInfo,
                                DateTime.UtcNow,
                                "",
                                "",
                                isVulnerable,
                                vulnInfo,
                                portEntry.Value
                            );

                            results.Add(result);
                        }
                    }
                    catch (SocketException)
                    {
                        // Port is closed - expected behavior
                    }
                    catch (OperationCanceledException)
                    {
                        // Scan was cancelled or timed out - expected behavior
                    }
                    catch (Exception)
                    {
                        // Other connection errors - continue with next port
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });
            
            try
            {
                await Task.WhenAll(tasks);
            }
            catch (Exception)
            {
                // Ignore aggregate exceptions - individual task errors are already handled
            }
        }

        private static async Task<string> GetHttpsServerInfo(string ipAddress, int port, CancellationToken cancellationToken = default)
        {
            try
            {
                using var client = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(TimeSpan.FromMilliseconds(1000)); // 1 second max for connection
                
                await client.ConnectAsync(ipAddress, port).WaitAsync(connectCts.Token);
                
                var sslStream = new System.Net.Security.SslStream(client.GetStream(), false, (sender, certificate, chain, errors) => true);
                
                using var sslCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                sslCts.CancelAfter(TimeSpan.FromMilliseconds(2000)); // 2 seconds max for SSL handshake
                
                await sslStream.AuthenticateAsClientAsync(ipAddress).WaitAsync(sslCts.Token);
                
                var cert = sslStream.RemoteCertificate as System.Security.Cryptography.X509Certificates.X509Certificate2;
                if (cert != null)
                {
                    return $"SSL: {cert.Subject} (Expires: {cert.NotAfter:yyyy-MM-dd})";
                }
            }
            catch
            {
                // Ignore SSL errors for scanning purposes - many reasons this can fail
            }
            return "";
        }

        /// <summary>
        /// Scans a single port on a specific IP address
        /// </summary>
        public static async Task<bool> ScanPortAsync(IPAddress ipAddress, int port, int timeout)
        {
            if (port < 1 || port > 65535)
                throw new ArgumentOutOfRangeException(nameof(port), "Port must be between 1 and 65535");

            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);
                var timeoutTask = Task.Delay(timeout);
                
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                
                if (completedTask == connectTask && client.Connected)
                {
                    return true;
                }
            }
            catch
            {
                // Port is closed or unreachable
            }
            
            return false;
        }

        /// <summary>
        /// Pings a host and returns the result using cross-platform connectivity test
        /// </summary>
        public static async Task<(bool Success, long ResponseTime)> PingHostAsync(IPAddress ipAddress, int timeout)
        {
            // Special handling for localhost/loopback - always consider reachable
            if (IPAddress.IsLoopback(ipAddress))
            {
                return (true, 1); // Localhost is always reachable with minimal latency
            }
            
            // First try native ping if available
            try
            {
                using var ping = new Ping();
                using var cts = new CancellationTokenSource(timeout + 1000); // Add buffer to timeout
                
                var reply = await ping.SendPingAsync(ipAddress, timeout).WaitAsync(cts.Token);
                
                if (reply.Status == IPStatus.Success)
                {
                    return (true, reply.RoundtripTime);
                }
            }
            catch (PlatformNotSupportedException)
            {
                // Native ping not available, fall back to TCP connectivity test
                return await TcpConnectivityTest(ipAddress, timeout);
            }
            catch (OperationCanceledException)
            {
                // Ping timed out - for localhost, still return success in test environment
                if (IPAddress.IsLoopback(ipAddress))
                {
                    return (true, timeout);
                }
                return (false, 0);
            }
            catch (Exception ex) when (ex.Message.Contains("Operation not permitted") || 
                                     ex.Message.Contains("Permission denied") ||
                                     ex.InnerException?.Message.Contains("Operation not permitted") == true)
            {
                // ICMP ping requires elevated privileges in some environments
                // Fall back to TCP connectivity test
                return await TcpConnectivityTest(ipAddress, timeout);
            }
            catch
            {
                // Other ping failures, try TCP fallback
                return await TcpConnectivityTest(ipAddress, timeout);
            }
            
            return (false, 0);
        }

        /// <summary>
        /// Cross-platform connectivity test using TCP connection to common ports
        /// </summary>
        private static async Task<(bool Success, long ResponseTime)> TcpConnectivityTest(IPAddress ipAddress, int timeout)
        {
            // Special handling for localhost/loopback
            if (IPAddress.IsLoopback(ipAddress))
            {
                return (true, 1); // Localhost is always reachable
            }
            
            var commonPorts = new[] { 80, 443, 22, 21, 23, 25, 53, 110, 995, 993, 143, 3389 };
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            try
            {
                // Create timeout token for the entire operation
                using var timeoutCts = new CancellationTokenSource(timeout);
                
                // Try multiple ports in parallel to increase chance of success
                var portTimeout = Math.Max(timeout / commonPorts.Length, 100); // At least 100ms per port
                var tasks = commonPorts.Select(port => 
                    TestTcpConnection(ipAddress, port, portTimeout, timeoutCts.Token)).ToArray();
                
                // Wait for any connection to succeed or all to complete
                var completedTask = await Task.WhenAny(tasks);
                stopwatch.Stop();
                
                var result = await completedTask;
                if (result)
                {
                    return (true, stopwatch.ElapsedMilliseconds);
                }
                
                // If no single connection succeeded quickly, wait a bit more for any to complete
                var remainingTimeout = Math.Max(timeout / 2, 200);
                using var finalCts = new CancellationTokenSource(remainingTimeout);
                
                try
                {
                    await Task.Delay(remainingTimeout, finalCts.Token);
                }
                catch (OperationCanceledException)
                {
                    // Expected timeout
                }
                
                // Check if any connection succeeded
                foreach (var task in tasks.Where(t => t.IsCompleted))
                {
                    try
                    {
                        if (await task)
                        {
                            return (true, stopwatch.ElapsedMilliseconds);
                        }
                    }
                    catch
                    {
                        // Ignore individual task errors
                    }
                }
            }
            catch (Exception)
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
        /// Tests TCP connection to a specific port
        /// </summary>
        private static async Task<bool> TestTcpConnection(IPAddress ipAddress, int port, int timeout, CancellationToken cancellationToken = default)
        {
            try
            {
                using var client = new TcpClient();
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(timeout);
                
                var connectTask = client.ConnectAsync(ipAddress, port);
                await connectTask.WaitAsync(timeoutCts.Token);
                
                return client.Connected;
            }
            catch
            {
                // Connection failed or timed out
                return false;
            }
        }

        /// <summary>
        /// Scans a single host for open ports and vulnerabilities.
        /// </summary>
        public static async Task<HostScanResult> ScanHostAsync(string ipAddress, Dictionary<int, string> ports, int timeout)
        {
            var ip = IPAddress.Parse(ipAddress);
            var result = new HostScanResult
            {
                IpAddress = ipAddress,
                OpenPorts = new List<ScanResult>()
            };

            result.PingResult = await PingHostAsync(ip, timeout);

            if (result.PingResult.Success)
            {
                var pingMs = result.PingResult.ResponseTime;
                var portScanTasks = ports.Select(async portEntry =>
                {
                    var isOpen = await TestTcpConnection(ip, portEntry.Key, timeout, CancellationToken.None);
                    if (!isOpen)
                        return default(ScanResult);

                    var serverInfo = string.Empty;
                    if (portEntry.Key == 443 || portEntry.Value == "HTTPS")
                        serverInfo = await GetHttpsServerInfo(ipAddress, portEntry.Key, CancellationToken.None) ?? string.Empty;

                    // Perform reverse DNS lookup
                    var hostname = await DnsLookupHelper.GetHostnameAsync(ip, 2000);

                    var scanRes = new ScanResult(
                        ip,
                        portEntry.Key,
                        true,
                        portEntry.Value,
                        pingMs,
                        NetworkUtilities.GuessOperatingSystem((int)pingMs),
                        serverInfo,
                        DateTime.UtcNow,
                        "",
                        hostname
                    );

                    if (NetworkConstants.VulnerablePorts.TryGetValue(portEntry.Key, out var vulnInfo))
                        scanRes = scanRes.WithVulnerability(vulnInfo);

                    return scanRes;
                });

                var portResults = await Task.WhenAll(portScanTasks);
                result.OpenPorts = portResults.Where(r => r.IsOpen).ToList();
            }

            return result;
        }

        /// <summary>
        /// Scans a network range for open ports
        /// </summary>
        public static async Task<List<ScanResult>> ScanNetworkRangeAsync(string baseIp, int startRange, int endRange, 
            Dictionary<int, string> ports, int timeout)
        {
            if (string.IsNullOrWhiteSpace(baseIp) || !baseIp.EndsWith("."))
                throw new ArgumentException("Invalid base IP format", nameof(baseIp));

            var results = new ConcurrentBag<ScanResult>();
            var semaphore = new SemaphoreSlim(50); // Limit concurrent operations

            var tasks = new List<Task>();
            for (int i = startRange; i <= endRange; i++)
            {
                var ipAddress = $"{baseIp}{i}";
                
                await semaphore.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var hostResult = await ScanHostAsync(ipAddress, ports, timeout);
                        foreach (var openPort in hostResult.OpenPorts)
                        {
                            results.Add(openPort);
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);
            return results.ToList();
        }

        /// <summary>
        /// Validates a port range
        /// </summary>
        public static bool ValidatePortRange(int startPort, int endPort)
        {
            return NetworkUtilities.IsValidPortRange(startPort, endPort);
        }

        /// <summary>
        /// Helper class for host scan results
        /// </summary>
        public class HostScanResult
        {
            public string IpAddress { get; set; } = string.Empty;
            public (bool Success, long ResponseTime) PingResult { get; set; }
            public List<ScanResult> OpenPorts { get; set; } = new();
        }
    }
}
