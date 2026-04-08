using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Discovery.Core.Utilities;
using Discovery.Services.Scanning;
using Spectre.Console;

namespace Discovery.Tools.RouterScanning
{
    /// <summary>
    /// Router scanning manager that coordinates all router-specific scanners with comprehensive batch scanning capabilities
    /// </summary>
    public static class RouterScanManager
    {
        /// <summary>
        /// Perform comprehensive router discovery and analysis
        /// </summary>
        public static async Task<List<RouterScanResult>> ScanForRoutersAsync(IPAddress startIp, IPAddress endIp)
        {
            var results = new List<RouterScanResult>();
            var tasks = new List<Task<RouterScanResult>>();

            AnsiConsole.MarkupLine("[bold cyan]🔍 Starting comprehensive router discovery scan...[/]");

            // Generate IP range
            var ipList = GenerateIpRange(startIp, endIp);
            
            AnsiConsole.MarkupLine($"[yellow]📊 Scanning {ipList.Count} IP addresses for router devices...[/]");

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
                    var task = ctx.AddTask("[yellow]Router discovery in progress...[/]", maxValue: ipList.Count);

                    foreach (var ip in ipList)
                    {
                        try
                        {
                            var result = await ScanSingleRouterAsync(ip);
                            if (result.IsRouter)
                            {
                                results.Add(result);
                                AnsiConsole.MarkupLine($"[green]✅ Router found at {ip} - {result.Brand}[/]");
                            }
                        }
                        catch (Exception ex)
                        {
                            AnsiConsole.MarkupLine($"[red]❌ Error scanning {ip}: {ex.Message}[/]");
                        }
                        
                        task.Increment(1);
                    }
                });

            return results;
        }

        /// <summary>
        /// Scan a single IP address for router identification and security assessment
        /// </summary>
        public static async Task<RouterScanResult> ScanSingleRouterAsync(IPAddress ipAddress)
        {
            var result = new RouterScanResult { IpAddress = ipAddress };

            try
            {
                // First, perform router fingerprinting
                var identification = await RouterFingerprinter.IdentifyRouterAsync(ipAddress);
                
                result.Brand = identification.Brand.ToString();
                result.Model = identification.Model;
                result.Firmware = identification.Firmware;
                result.ManagementInterface = identification.ManagementInterface;
                result.ManagementPorts = identification.ManagementPorts;
                result.ConfidenceScore = identification.ConfidenceScore;
                result.DetectionMethods = identification.DetectionMethods;

                if (identification.Brand != RouterFingerprinter.RouterBrand.Unknown)
                {
                    result.IsRouter = true;

                    // Perform brand-specific detailed scanning
                    switch (identification.Brand)
                    {
                        case RouterFingerprinter.RouterBrand.Cisco:
                            var ciscoDevice = await CiscoScanner.ScanCiscoDeviceAsync(ipAddress);
                            result.DetailedInfo = ConvertCiscoToGeneric(ciscoDevice);
                            break;

                        case RouterFingerprinter.RouterBrand.Mikrotik:
                            var mikrotikDevice = await MikroTikScanner.ScanMikroTikDeviceAsync(ipAddress);
                            result.DetailedInfo = ConvertMikroTikToGeneric(mikrotikDevice);
                            break;

                        case RouterFingerprinter.RouterBrand.Ubiquiti:
                            result.DetailedInfo = await ScanUbiquitiDeviceAsync(ipAddress);
                            break;

                        case RouterFingerprinter.RouterBrand.Netgear:
                            result.DetailedInfo = await ScanNetgearDeviceAsync(ipAddress);
                            break;

                        case RouterFingerprinter.RouterBrand.TPLink:
                            result.DetailedInfo = await ScanTPLinkDeviceAsync(ipAddress);
                            break;

                        default:
                            result.DetailedInfo = await ScanGenericRouterAsync(ipAddress);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                result.ScanError = ex.Message;
            }

            return result;
        }

        private static Dictionary<string, object> ConvertCiscoToGeneric(CiscoScanner.CiscoDevice ciscoDevice)
        {
            return new Dictionary<string, object>
            {
                ["OpenPorts"] = ciscoDevice.OpenPorts,
                ["Services"] = ciscoDevice.Services,
                ["SecurityFindings"] = ciscoDevice.SecurityFindings.Count,
                ["IosVersion"] = ciscoDevice.IosVersion,
                ["Model"] = ciscoDevice.Model,
                ["Hostname"] = ciscoDevice.Hostname,
                ["EnabledProtocols"] = ciscoDevice.EnabledProtocols
            };
        }

        private static Dictionary<string, object> ConvertMikroTikToGeneric(MikroTikScanner.MikroTikDevice mikrotikDevice)
        {
            return new Dictionary<string, object>
            {
                ["OpenPorts"] = mikrotikDevice.OpenPorts,
                ["Services"] = mikrotikDevice.Services,
                ["SecurityFindings"] = mikrotikDevice.SecurityFindings.Count,
                ["RouterOsVersion"] = mikrotikDevice.RouterOsVersion,
                ["Model"] = mikrotikDevice.Model,
                ["WinboxEnabled"] = mikrotikDevice.WinboxEnabled,
                ["ApiEnabled"] = mikrotikDevice.ApiEnabled,
                ["WebfigEnabled"] = mikrotikDevice.WebfigEnabled
            };
        }

        private static async Task<Dictionary<string, object>> ScanUbiquitiDeviceAsync(IPAddress ipAddress)
        {
            var info = new Dictionary<string, object>();
            
            // Basic Ubiquiti device scanning
            var commonPorts = new[] { 22, 80, 443, 8080, 8443, 8880, 8843 };
            var openPorts = new List<int>();

            foreach (var port in commonPorts)
            {
                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask)
                    {
                        await connectTask;
                        openPorts.Add(port);
                    }
                }
                catch { }
            }

            info["OpenPorts"] = openPorts;
            info["DeviceType"] = "Ubiquiti Network Device";
            info["CommonServices"] = new List<string> { "UniFi Controller", "EdgeRouter Management" };
            
            return info;
        }

        private static async Task<Dictionary<string, object>> ScanNetgearDeviceAsync(IPAddress ipAddress)
        {
            var info = new Dictionary<string, object>();
            
            // Basic Netgear device scanning
            var commonPorts = new[] { 22, 23, 80, 443, 8080 };
            var openPorts = new List<int>();

            foreach (var port in commonPorts)
            {
                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask)
                    {
                        await connectTask;
                        openPorts.Add(port);
                    }
                }
                catch { }
            }

            info["OpenPorts"] = openPorts;
            info["DeviceType"] = "Netgear Router/Switch";
            info["CommonVulnerabilities"] = new List<string> { "Default credentials", "Web interface vulnerabilities" };
            
            return info;
        }

        private static async Task<Dictionary<string, object>> ScanTPLinkDeviceAsync(IPAddress ipAddress)
        {
            var info = new Dictionary<string, object>();
            
            // Basic TP-Link device scanning
            var commonPorts = new[] { 22, 23, 80, 443, 8080 };
            var openPorts = new List<int>();

            foreach (var port in commonPorts)
            {
                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask)
                    {
                        await connectTask;
                        openPorts.Add(port);
                    }
                }
                catch { }
            }

            info["OpenPorts"] = openPorts;
            info["DeviceType"] = "TP-Link Router/Access Point";
            info["CommonCredentials"] = new List<string> { "admin/admin", "admin/password" };
            
            return info;
        }

        private static async Task<Dictionary<string, object>> ScanGenericRouterAsync(IPAddress ipAddress)
        {
            var info = new Dictionary<string, object>();
            
            // Generic router scanning for unknown brands
            var commonPorts = new[] { 21, 22, 23, 53, 80, 443, 161, 8080, 8443 };
            var openPorts = new List<int>();

            foreach (var port in commonPorts)
            {
                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask)
                    {
                        await connectTask;
                        openPorts.Add(port);
                    }
                }
                catch { }
            }

            info["OpenPorts"] = openPorts;
            info["DeviceType"] = "Generic Network Device";
            info["RequiresFurtherAnalysis"] = true;
            
            return info;
        }

        private static List<IPAddress> GenerateIpRange(IPAddress startIp, IPAddress endIp)
        {
            var ipList = new List<IPAddress>();
            
            var start = BitConverter.ToUInt32(startIp.GetAddressBytes().Reverse().ToArray(), 0);
            var end = BitConverter.ToUInt32(endIp.GetAddressBytes().Reverse().ToArray(), 0);

            for (uint i = start; i <= end; i++)
            {
                var bytes = BitConverter.GetBytes(i).Reverse().ToArray();
                ipList.Add(new IPAddress(bytes));
            }

            return ipList;
        }

        /// <summary>
        /// Display comprehensive router scan results
        /// </summary>
        public static void DisplayRouterScanResults(List<RouterScanResult> results)
        {
            if (results.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No routers detected in the specified range.[/]");
                return;
            }

            var table = new Table()
                .Border(TableBorder.Rounded)
                .Title("[bold yellow]Router Discovery Results[/]")
                .AddColumn("[bold]IP Address[/]")
                .AddColumn("[bold]Brand[/]")
                .AddColumn("[bold]Model[/]")
                .AddColumn("[bold]Firmware[/]")
                .AddColumn("[bold]Management[/]")
                .AddColumn("[bold]Confidence[/]")
                .AddColumn("[bold]Security Risk[/]");

            foreach (var result in results.Where(r => r.IsRouter))
            {
                var riskLevel = CalculateRiskLevel(result);
                var riskColor = riskLevel switch
                {
                    "High" => "red",
                    "Medium" => "yellow",
                    "Low" => "green",
                    _ => "white"
                };

                table.AddRow(
                    result.IpAddress.ToString(),
                    result.Brand ?? "Unknown",
                    result.Model ?? "Unknown",
                    result.Firmware ?? "Unknown",
                    string.Join(", ", result.ManagementPorts.Take(3)),
                    $"{result.ConfidenceScore:F1}%",
                    $"[{riskColor}]{riskLevel}[/]"
                );
            }

            AnsiConsole.Write(table);

            // Display summary statistics
            DisplayScanSummary(results);
        }

        private static string CalculateRiskLevel(RouterScanResult result)
        {
            if (result.DetailedInfo != null && result.DetailedInfo.ContainsKey("SecurityFindings"))
            {
                var findings = (int)result.DetailedInfo["SecurityFindings"];
                return findings switch
                {
                    >= 5 => "High",
                    >= 2 => "Medium",
                    _ => "Low"
                };
            }

            // Default risk assessment based on open management ports
            var riskPorts = new[] { 23, 80, 8291 }; // Telnet, HTTP, Winbox
            if (result.ManagementPorts.Any(p => riskPorts.Contains(p)))
            {
                return "Medium";
            }

            return "Low";
        }

        private static void DisplayScanSummary(List<RouterScanResult> results)
        {
            var routerResults = results.Where(r => r.IsRouter).ToList();
            
            var summary = new Panel(
                $"[bold cyan]Total IPs Scanned:[/] {results.Count}\n" +
                $"[bold green]Routers Detected:[/] {routerResults.Count}\n" +
                $"[bold blue]Brands Identified:[/] {routerResults.Select(r => r.Brand).Distinct().Count()}\n" +
                $"[bold yellow]High Risk Devices:[/] {routerResults.Count(r => CalculateRiskLevel(r) == "High")}\n" +
                $"[bold orange3]Medium Risk Devices:[/] {routerResults.Count(r => CalculateRiskLevel(r) == "Medium")}"
            )
            .Header("[bold yellow]Scan Summary[/]")
            .BorderColor(Color.Blue)
            .Padding(1, 1);

            AnsiConsole.Write(summary);
        }

        // ===== BATCH SCANNING METHODS =====

        /// <summary>
        /// Scans routers from a CSV list containing IP addresses, CIDR networks, and IP ranges
        /// </summary>
        /// <param name="csvContent">CSV content with targets (IPs, CIDRs, ranges)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of router scan results</returns>
        public static async Task<List<RouterScanResult>> ScanRoutersFromCsvAsync(string csvContent, CancellationToken cancellationToken = default)
        {
            var targets = ParseCsvTargets(csvContent);
            return await ScanBatchRoutersAsync(targets, cancellationToken);
        }

        /// <summary>
        /// Scans routers in a CIDR network range
        /// </summary>
        /// <param name="cidrNotation">CIDR notation (e.g., 192.168.1.0/24)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of router scan results</returns>
        public static async Task<List<RouterScanResult>> ScanRoutersCidrAsync(string cidrNotation, CancellationToken cancellationToken = default)
        {
            var targets = new[] { cidrNotation };
            return await ScanBatchRoutersAsync(targets, cancellationToken);
        }

        /// <summary>
        /// Scans routers in an IP range
        /// </summary>
        /// <param name="startIp">Starting IP address</param>
        /// <param name="endIp">Ending IP address</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of router scan results</returns>
        public static async Task<List<RouterScanResult>> ScanRoutersIpRangeAsync(string startIp, string endIp, CancellationToken cancellationToken = default)
        {
            var rangeTarget = $"{startIp}-{endIp}";
            var targets = new[] { rangeTarget };
            return await ScanBatchRoutersAsync(targets, cancellationToken);
        }

        /// <summary>
        /// Scans multiple router targets from a list of target strings (IPs, CIDRs, ranges)
        /// </summary>
        /// <param name="targets">Collection of target strings</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of router scan results</returns>
        public static async Task<List<RouterScanResult>> ScanBatchRoutersAsync(IEnumerable<string> targets, CancellationToken cancellationToken = default)
        {
            var allResults = new List<RouterScanResult>();
            var expandedIps = ExpandTargetsToIps(targets).Distinct().ToList();
            
            // Skip interactive prompts in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment && expandedIps.Count > 50)
            {
                var confirm = AnsiConsole.Confirm($"About to scan {expandedIps.Count} IP addresses for routers. This may take a while. Continue?");
                if (!confirm)
                {
                    AnsiConsole.MarkupLine("[yellow]Router scan cancelled by user.[/]");
                    return allResults;
                }
            }

            AnsiConsole.MarkupLine($"[bold cyan]🔍 Starting batch router scan on {expandedIps.Count} targets...[/]");

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
                    var task = ctx.AddTask("[yellow]Scanning for routers...[/]", maxValue: expandedIps.Count);
                    
                    // Use a semaphore to limit concurrent scans
                    using var semaphore = new SemaphoreSlim(Math.Min(20, expandedIps.Count), Math.Min(20, expandedIps.Count));
                    
                    var tasks = expandedIps.Select(async ip =>
                    {
                        await semaphore.WaitAsync(cancellationToken);
                        try
                        {
                            if (IPAddress.TryParse(ip, out var ipAddress))
                            {
                                var result = await ScanSingleRouterAsync(ipAddress);
                                task.Increment(1);
                                return result;
                            }
                            task.Increment(1);
                            return null;
                        }
                        catch (Exception ex)
                        {
                            // Log error but continue with other IPs
                            if (!TestEnvironmentDetector.IsTestEnvironment)
                                AnsiConsole.MarkupLine($"[red]Error scanning {ip}: {ex.Message}[/]");
                            task.Increment(1);
                            return null;
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    });

                    var results = await Task.WhenAll(tasks);
                    
                    foreach (var result in results)
                    {
                        if (result != null)
                            allResults.Add(result);
                    }
                });

            var routersFound = allResults.Where(r => r.IsRouter).ToList();
            
            if (!TestEnvironmentDetector.IsTestEnvironment)
            {
                AnsiConsole.MarkupLine($"[bold green]✅ Router scan completed: {routersFound.Count} routers found out of {expandedIps.Count} targets[/]");
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
                // Skip empty lines and comments
                var trimmedLine = line.Trim();
                if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#") || trimmedLine.StartsWith("//"))
                    continue;

                // Split by comma, semicolon, or whitespace and process each part
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

            // Check if it's a CIDR notation
            if (target.Contains('/'))
            {
                foreach (var ip in ExpandCidrToIps(target))
                    yield return ip;
            }
            // Check if it's an IP range (e.g., 192.168.1.1-192.168.1.10 or 192.168.1.1-10)
            else if (target.Contains('-'))
            {
                foreach (var ip in ExpandRangeToIps(target))
                    yield return ip;
            }
            // Check if it's a single IP address
            else if (IPAddress.TryParse(target, out _))
            {
                yield return target;
            }
            // Check if it's a hostname - resolve to IP
            else if (IsValidHostname(target))
            {
                var resolvedIps = ResolveHostnameToIps(target);
                foreach (var ip in resolvedIps)
                    yield return ip;
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
            
            // Skip network and broadcast addresses for /24 and smaller subnets
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

            // Check if end part is a full IP or just the last octet
            if (IPAddress.TryParse(endPart, out var endAddress))
            {
                // Full IP address range
                foreach (var ip in GetIpRange(startAddress, endAddress))
                    yield return ip;
            }
            else if (int.TryParse(endPart, out var endOctet) && endOctet >= 0 && endOctet <= 255)
            {
                // Last octet range (e.g., 192.168.1.1-10)
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

        private static bool IsValidHostname(string hostname)
        {
            if (string.IsNullOrWhiteSpace(hostname) || hostname.Length > 253)
                return false;

            // Basic hostname validation regex
            var hostnameRegex = new System.Text.RegularExpressions.Regex(@"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");
            return hostnameRegex.IsMatch(hostname);
        }

        private static IEnumerable<string> ResolveHostnameToIps(string hostname)
        {
            try
            {
                var hostEntry = Dns.GetHostEntry(hostname);
                return hostEntry.AddressList
                    .Where(addr => addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(addr => addr.ToString());
            }
            catch
            {
                // DNS resolution failed, return empty
                return Enumerable.Empty<string>();
            }
        }
    }

    /// <summary>
    /// Router scan result model
    /// </summary>
    public class RouterScanResult
    {
        public IPAddress IpAddress { get; set; } = IPAddress.None;
        public bool IsRouter { get; set; }
        public string? Brand { get; set; }
        public string? Model { get; set; }
        public string? Firmware { get; set; }
        public string? ManagementInterface { get; set; }
        public List<int> ManagementPorts { get; set; } = new();
        public float ConfidenceScore { get; set; }
        public List<string> DetectionMethods { get; set; } = new();
        public Dictionary<string, object>? DetailedInfo { get; set; }
        public string? ScanError { get; set; }
    }
}