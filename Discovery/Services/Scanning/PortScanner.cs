using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
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
    /// Implementation of port scanning operations with comprehensive batch scanning capabilities
    /// </summary>
    public class PortScanner : BaseBatchScanner, IScanner
    {
        private readonly int _timeout;
        private readonly int _maxConcurrency;

        public PortScanner(int timeout = 1000, int maxConcurrency = 200)
        {
            _timeout = timeout;
            _maxConcurrency = maxConcurrency;
        }

        /// <summary>
        /// Scans a single IP address for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanSingleIpAsync(string ipAddress, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            if (!IPAddress.TryParse(ipAddress, out _))
            {
                throw new ArgumentException("Invalid IP address format", nameof(ipAddress));
            }

            var results = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
            LiveScanDisplay? liveDisplay = null;
            
            // Only use interactive display when not running in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment)
            {
                liveDisplay = new LiveScanDisplay(results);
                
                AnsiConsole.MarkupLine("[bold cyan]🔍 Starting single IP scan with live results...[/]");
                AnsiConsole.MarkupLine($"[yellow]Target: {ipAddress}[/]");
                AnsiConsole.MarkupLine($"[yellow]Ports: {portsToScan.Count}[/]");
                AnsiConsole.WriteLine();
                
                liveDisplay.StartLiveDisplay();
            }
            
            try
            {
                // Ping the host first to determine if it's alive
                var pingResult = await PingHostAsync(IPAddress.Parse(ipAddress), _timeout);
                
                if (pingResult.Success)
                {
                    var os = NetworkConstants.GuessOperatingSystem(0); // We don't have TTL from TCP test
                    await ScanPortsAsync(ipAddress, results, portsToScan, pingResult.ResponseTime, os, cancellationToken);
                }
                else
                {
                    if (!TestEnvironmentDetector.IsTestEnvironment)
                    {
                        AnsiConsole.MarkupLine($"[yellow]Host {ipAddress} appears to be offline or not responding to ping.[/]");
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
        /// Scans a range of IP addresses for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanNetworkRangeAsync(string baseIp, int startRange, int endRange, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var results = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
            LiveScanDisplay? liveDisplay = null;
            
            // Only use interactive display when not running in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment)
            {
                liveDisplay = new LiveScanDisplay(results);
                
                AnsiConsole.MarkupLine("[bold cyan]🔍 Starting network scan with live results...[/]");
                AnsiConsole.MarkupLine($"[yellow]🌐 Scanning range: {baseIp}{startRange}-{endRange} ({endRange - startRange + 1} IPs)[/]");
                AnsiConsole.MarkupLine($"[yellow]🔌 Ports per host: {portsToScan.Count}[/]");
                AnsiConsole.WriteLine();
                
                liveDisplay.StartLiveDisplay();
            }
            
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
                        var semaphore = new SemaphoreSlim(_maxConcurrency);
                        
                        scanTask.MaxValue = endRange - startRange + 1;

                        for (int i = startRange; i <= endRange; i++)
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            string ipToScan = baseIp + i;
                            
                            await semaphore.WaitAsync(cancellationToken);
                            tasks.Add(Task.Run(async () =>
                            {
                                try
                                {
                                    await PingAndScanPortsAsync(ipToScan, results, portsToScan, cancellationToken);
                                }
                                finally
                                {
                                    scanTask.Increment(1);
                                    semaphore.Release();
                                }
                            }, cancellationToken));
                        }
                        
                        await Task.WhenAll(tasks);
                    });
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
        /// Scans a CIDR network for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanCidrNetworkAsync(IPAddress networkAddress, int subnetMask, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var results = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
            var networkBytes = networkAddress.GetAddressBytes();
            uint network = (uint)networkBytes[0] << 24 | (uint)networkBytes[1] << 16 | (uint)networkBytes[2] << 8 | networkBytes[3];
            
            uint mask = 0xFFFFFFFF << (32 - subnetMask);
            network = network & mask;
            
            uint hostBits = (uint)(32 - subnetMask);
            uint totalHosts = (uint)(Math.Pow(2, hostBits) - 2); // Exclude network and broadcast addresses
            
            if (totalHosts > 65536)
            {
                if (!TestEnvironmentDetector.IsTestEnvironment && 
                    !AnsiConsole.Confirm($"[yellow]Warning: You are about to scan {totalHosts} IP addresses. This could take a very long time. Are you sure?[/]"))
                {
                    return results.ToList();
                }
            }

            LiveScanDisplay? liveDisplay = null;
            
            // Only use interactive display when not running in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment)
            {
                liveDisplay = new LiveScanDisplay(results, (int)totalHosts);
                
                AnsiConsole.MarkupLine("[bold cyan]🔍 Starting CIDR network scan with live results...[/]");
                AnsiConsole.MarkupLine($"[yellow]Network: {networkAddress}/{subnetMask} ({totalHosts} hosts)[/]");
                AnsiConsole.MarkupLine($"[yellow]Ports per host: {portsToScan.Count}[/]");
                AnsiConsole.WriteLine();
                
                liveDisplay.StartLiveDisplay();
            }

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
                        var scanTask = ctx.AddTask("[green]Scanning CIDR network[/]");
                        scanTask.MaxValue = totalHosts;
                        var tasks = new List<Task>();
                        var semaphore = new SemaphoreSlim(_maxConcurrency);

                        for (uint i = 1; i <= totalHosts; i++)
                        {
                            if (cancellationToken.IsCancellationRequested) break;

                            uint currentIp = network + i;
                            var currentIpBytes = new byte[4];
                            currentIpBytes[0] = (byte)(currentIp >> 24);
                            currentIpBytes[1] = (byte)(currentIp >> 16);
                            currentIpBytes[2] = (byte)(currentIp >> 8);
                            currentIpBytes[3] = (byte)currentIp;
                            var ipToScan = new IPAddress(currentIpBytes).ToString();

                            await semaphore.WaitAsync(cancellationToken);
                            tasks.Add(Task.Run(async () =>
                            {
                                try
                                {
                                    await PingAndScanPortsAsync(ipToScan, results, portsToScan, cancellationToken);
                                }
                                finally
                                {
                                    scanTask.Increment(1);
                                    semaphore.Release();
                                }
                            }, cancellationToken));
                        }
                        await Task.WhenAll(tasks);
                    });
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
        /// Scans a range of public IP addresses for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanPublicIpRangeAsync(IPAddress startIp, IPAddress endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var results = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
            
            byte[] startBytes = startIp.GetAddressBytes();
            byte[] endBytes = endIp.GetAddressBytes();
            
            uint start = (uint)startBytes[0] << 24 | (uint)startBytes[1] << 16 | (uint)startBytes[2] << 8 | startBytes[3];
            uint end = (uint)endBytes[0] << 24 | (uint)endBytes[1] << 16 | (uint)endBytes[2] << 8 | endBytes[3];
            
            if (start > end)
            {
                throw new ArgumentException("Start IP must be less than or equal to End IP");
            }
            
            long totalIps = (long)end - start + 1;
            if (totalIps > 65536)
            {
                if (!TestEnvironmentDetector.IsTestEnvironment && 
                    !AnsiConsole.Confirm($"[yellow]Warning: You are about to scan {totalIps} IP addresses. This could take a very long time. Are you sure?[/]"))
                {
                    return results.ToList();
                }
            }

            LiveScanDisplay? liveDisplay = null;
            
            // Only use interactive display when not running in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment)
            {
                liveDisplay = new LiveScanDisplay(results);
                
                AnsiConsole.MarkupLine("[bold cyan]🔍 Starting public IP range scan with live results...[/]");
                AnsiConsole.MarkupLine($"[yellow]Range: {startIp} - {endIp} ({totalIps} IPs)[/]");
                AnsiConsole.MarkupLine($"[yellow]Ports per host: {portsToScan.Count}[/]");
                AnsiConsole.WriteLine();
                
                liveDisplay.StartLiveDisplay();
            }

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
                        var scanTask = ctx.AddTask("[green]Scanning network[/]");
                        scanTask.MaxValue = totalIps;
                        var tasks = new List<Task>();
                        var semaphore = new SemaphoreSlim(_maxConcurrency);

                        for (uint i = start; i <= end; i++)
                        {
                            if (cancellationToken.IsCancellationRequested) break;

                            var currentIpBytes = new byte[4];
                            currentIpBytes[0] = (byte)(i >> 24);
                            currentIpBytes[1] = (byte)(i >> 16);
                            currentIpBytes[2] = (byte)(i >> 8);
                            currentIpBytes[3] = (byte)i;
                            var ipToScan = new IPAddress(currentIpBytes).ToString();

                            await semaphore.WaitAsync(cancellationToken);
                            tasks.Add(Task.Run(async () =>
                            {
                                try
                                {
                                    await PingAndScanPortsAsync(ipToScan, results, portsToScan, cancellationToken);
                                }
                                finally
                                {
                                    scanTask.Increment(1);
                                    semaphore.Release();
                                }
                            }, cancellationToken));
                        }
                        await Task.WhenAll(tasks);
                    });
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

        #region Helper Methods

        /// <summary>
        /// Tests if a single port is open on a given IP address (public method for external use)
        /// </summary>
        public async Task<bool> ScanPortAsync(IPAddress ipAddress, int port, int timeout = 1000)
        {
            return await ScanPortInternalAsync(ipAddress, port, timeout);
        }

        /// <summary>
        /// Tests if a single port is open on a given IP address
        /// </summary>
        private async Task<bool> ScanPortInternalAsync(IPAddress ipAddress, int port, int timeout)
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
        private async Task<(bool Success, long ResponseTime)> PingHostAsync(IPAddress ipAddress, int timeout)
        {
            try
            {
                // Try cross-platform TCP connectivity test
                return await TcpConnectivityTest(ipAddress, timeout);
            }
            catch
            {
                return (false, 0);
            }
        }

        /// <summary>
        /// Cross-platform connectivity test using TCP connection to common ports
        /// </summary>
        private async Task<(bool Success, long ResponseTime)> TcpConnectivityTest(IPAddress ipAddress, int timeout)
        {
            var commonPorts = new[] { 80, 443, 22, 21, 23, 25, 53, 110, 995, 993, 143, 3389 };
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // ToList() is required because tasks are removed from the list during the loop.
            // The hardcoded commonPorts array is small (12 entries) so all tasks are created upfront.
            var tasks = commonPorts.Select(port => TestTcpConnection(ipAddress, port, timeout / commonPorts.Length)).ToList();
            
            try
            {
                // Keep checking as tasks complete; return as soon as one succeeds
                while (tasks.Count > 0)
                {
                    var completedTask = await Task.WhenAny(tasks);
                    tasks.Remove(completedTask);

                    if (await completedTask)
                    {
                        stopwatch.Stop();
                        return (true, stopwatch.ElapsedMilliseconds);
                    }
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
        /// Tests TCP connection to a specific port
        /// </summary>
        private async Task<bool> TestTcpConnection(IPAddress ipAddress, int port, int timeout)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);
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
        /// Pings a host and scans its ports if it's alive
        /// </summary>
        private async Task PingAndScanPortsAsync(string ipAddress, System.Collections.Concurrent.ConcurrentBag<ScanResult> results, Dictionary<int, string> portsToScan, CancellationToken token)
        {
            try
            {
                if (!IPAddress.TryParse(ipAddress, out var ip))
                    return;

                var pingResult = await PingHostAsync(ip, _timeout);
                if (pingResult.Success)
                {
                    var os = NetworkConstants.GuessOperatingSystem(0); // TTL not available with TCP test
                    await ScanPortsAsync(ipAddress, results, portsToScan, pingResult.ResponseTime, os, token);
                }
            }
            catch (OperationCanceledException)
            {
                // Scan was cancelled
            }
            catch (Exception)
            {
                // Host is not reachable or other error
            }
        }

        /// <summary>
        /// Scans all specified ports on a host and adds results to the collection
        /// </summary>
        private async Task ScanPortsAsync(string ipAddress, System.Collections.Concurrent.ConcurrentBag<ScanResult> results, Dictionary<int, string> portsToScan, long pingTime, string operatingSystem, CancellationToken token)
        {
            // Perform reverse DNS lookup once per host, not once per open port
            var hostname = await DnsLookupHelper.GetHostnameAsync(ipAddress, 2000);

            var tasks = portsToScan.Select(async portEntry =>
            {
                if (token.IsCancellationRequested) return;

                using var client = new TcpClient();
                try
                {
                    var connectTask = client.ConnectAsync(ipAddress, portEntry.Key);
                    if (await Task.WhenAny(connectTask, Task.Delay(_timeout, token)) == connectTask)
                    {
                        await connectTask;
                        
                        var serverInfo = "";
                        var isVulnerable = NetworkConstants.IsPortVulnerable(portEntry.Key);
                        var vulnInfo = isVulnerable ? NetworkConstants.GetPortVulnerabilityInfo(portEntry.Key) : "";
                        
                        if (portEntry.Key == 443 || portEntry.Value == "HTTPS")
                        {
                            serverInfo = await GetHttpsServerInfo(ipAddress, portEntry.Key);
                        }
                        
                        var scanResult = new ScanResult(
                            IPAddress.Parse(ipAddress), // ipAddress
                            portEntry.Key, // port
                            true, // isOpen
                            portEntry.Value, // service
                            pingTime, // pingTime
                            operatingSystem, // operatingSystem
                            serverInfo, // serverInfo
                            DateTime.UtcNow, // discoveredAt
                            "", // country
                            hostname, // hostname
                            isVulnerable, // isVulnerable
                            vulnInfo, // vulnerabilityInfo
                            portEntry.Value // serviceName
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
            });
            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Gets HTTPS server certificate information
        /// </summary>
        private async Task<string> GetHttpsServerInfo(string ipAddress, int port)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);
                if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
                {
                    return "Connection timed out";
                }
                
                await connectTask;
                
                using var sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate, null);
                try
                {
                    await sslStream.AuthenticateAsClientAsync(ipAddress);
                    var certificate = sslStream.RemoteCertificate as X509Certificate2 ?? 
                                      (sslStream.RemoteCertificate != null ? new X509Certificate2(sslStream.RemoteCertificate) : null);
                    
                    if (certificate != null)
                    {
                        return $"Subject: {certificate.Subject}, Issuer: {certificate.Issuer}, Valid until: {certificate.NotAfter.ToShortDateString()}";
                    }
                    else
                    {
                        return "SSL certificate not available";
                    }
                }
                catch (Exception ex)
                {
                    return $"SSL Error: {ex.Message}";
                }
            }
            catch (Exception)
            {
                return "Could not retrieve server info";
            }
        }

        private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            // Accept all certificates for scanning purposes
            return true;
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
        /// Performs host discovery via ping before port scanning
        /// </summary>
        private async Task ScanHostAsync(string ipAddress, System.Collections.Concurrent.ConcurrentBag<ScanResult> results, Dictionary<int, string> portsToScan, string operatingSystem, CancellationToken token)
        {
            try
            {
                if (!IPAddress.TryParse(ipAddress, out var ip))
                    return;

                var pingResult = await PingHostAsync(ip, _timeout);
                if (pingResult.Success)
                {
                    await ScanPortsAsync(ipAddress, results, portsToScan, pingResult.ResponseTime, operatingSystem, token);
                }
            }
            catch (OperationCanceledException)
            {
                // Scan was cancelled
            }
            catch (Exception)
            {
                // Host is not reachable or other error
            }
        }

        #endregion
    }
}
