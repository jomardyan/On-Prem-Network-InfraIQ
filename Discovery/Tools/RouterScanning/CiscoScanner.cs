using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Discovery.Core.Models;
using Spectre.Console;

namespace Discovery.Tools.RouterScanning
{
    /// <summary>
    /// Cisco-specific router scanning and security assessment tools
    /// </summary>
    public static class CiscoScanner
    {
        public class CiscoDevice
        {
            public IPAddress IpAddress { get; set; } = IPAddress.None;
            public string Model { get; set; } = "";
            public string IosVersion { get; set; } = "";
            public string SerialNumber { get; set; } = "";
            public string Hostname { get; set; } = "";
            public List<string> Interfaces { get; set; } = new();
            public List<int> OpenPorts { get; set; } = new();
            public List<string> Services { get; set; } = new();
            public List<SecurityFinding> SecurityFindings { get; set; } = new();
            public Dictionary<string, string> ConfigurationInfo { get; set; } = new();
            public bool HasDefaultCredentials { get; set; }
            public List<string> EnabledProtocols { get; set; } = new();
        }

        public class SecurityFinding
        {
            public string Category { get; set; } = "";
            public string Severity { get; set; } = "";
            public string Description { get; set; } = "";
            public string Recommendation { get; set; } = "";
            public string CveId { get; set; } = "";
        }

        private static readonly Dictionary<string, List<string>> CiscoDefaultCredentials = new()
        {
            ["admin"] = new List<string> { "admin", "cisco", "", "Admin" },
            ["cisco"] = new List<string> { "cisco", "", "admin" },
            ["root"] = new List<string> { "admin", "cisco" },
            ["enable"] = new List<string> { "cisco", "admin", "" },
            ["manager"] = new List<string> { "manager", "cisco" }
        };

        private static readonly int[] CiscoCommonPorts = {
            22,    // SSH
            23,    // Telnet
            80,    // HTTP
            443,   // HTTPS
            161,   // SNMP
            162,   // SNMP Trap
            514,   // Syslog
            1993,  // SNMP over TCP
            8080,  // HTTP Alt
            8443,  // HTTPS Alt
            9600   // SSH Alt
        };

        /// <summary>
        /// Comprehensive Cisco device scan and security assessment
        /// </summary>
        public static async Task<CiscoDevice> ScanCiscoDeviceAsync(IPAddress ipAddress)
        {
            var device = new CiscoDevice { IpAddress = ipAddress };

            AnsiConsole.MarkupLine($"[cyan]🔍 Scanning Cisco device at {ipAddress}...[/]");

            // Create progress display
            await AnsiConsole.Progress()
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn(),
                })
                .StartAsync(async ctx =>
                {
                    var task1 = ctx.AddTask("[yellow]Port scanning...[/]");
                    var task2 = ctx.AddTask("[cyan]Service detection...[/]");
                    var task3 = ctx.AddTask("[red]Security assessment...[/]");
                    var task4 = ctx.AddTask("[green]Configuration analysis...[/]");

                    // Port scanning
                    await ScanPortsAsync(device);
                    task1.Value = 100;

                    // Service detection
                    await DetectServicesAsync(device);
                    task2.Value = 100;

                    // Security assessment
                    await PerformSecurityAssessmentAsync(device);
                    task3.Value = 100;

                    // Configuration analysis
                    await AnalyzeConfigurationAsync(device);
                    task4.Value = 100;
                });

            return device;
        }

        private static async Task ScanPortsAsync(CiscoDevice device)
        {
            var tasks = CiscoCommonPorts.Select(async port =>
            {
                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(device.IpAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(2000)) == connectTask)
                    {
                        await connectTask;
                        device.OpenPorts.Add(port);
                    }
                }
                catch
                {
                    // Port closed or filtered
                }
            });

            await Task.WhenAll(tasks);
        }

        private static async Task DetectServicesAsync(CiscoDevice device)
        {
            foreach (var port in device.OpenPorts)
            {
                try
                {
                    switch (port)
                    {
                        case 22:
                            var sshBanner = await GetSshBannerAsync(device.IpAddress);
                            device.Services.Add($"SSH: {sshBanner}");
                            ExtractInfoFromSshBanner(device, sshBanner);
                            break;

                        case 23:
                            var telnetBanner = await GetTelnetBannerAsync(device.IpAddress);
                            device.Services.Add($"Telnet: {telnetBanner}");
                            ExtractInfoFromTelnetBanner(device, telnetBanner);
                            break;

                        case 80:
                        case 443:
                        case 8080:
                        case 8443:
                            var httpInfo = await GetHttpInfoAsync(device.IpAddress, port);
                            device.Services.Add($"HTTP({port}): {httpInfo}");
                            ExtractInfoFromHttpResponse(device, httpInfo);
                            break;

                        case 161:
                            device.Services.Add("SNMP v1/v2c");
                            device.EnabledProtocols.Add("SNMP");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    device.Services.Add($"Port {port}: Error - {ex.Message}");
                }
            }
        }

        private static async Task<string> GetSshBannerAsync(IPAddress ipAddress)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(ipAddress, 22);
                
                using var stream = client.GetStream();
                var buffer = new byte[1024];
                var received = await stream.ReadAsync(buffer, 0, buffer.Length);
                return Encoding.UTF8.GetString(buffer, 0, received).Trim();
            }
            catch
            {
                return "Banner not available";
            }
        }

        private static async Task<string> GetTelnetBannerAsync(IPAddress ipAddress)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(ipAddress, 23);
                
                using var stream = client.GetStream();
                var buffer = new byte[1024];
                var received = await stream.ReadAsync(buffer, 0, buffer.Length);
                return Encoding.UTF8.GetString(buffer, 0, received).Trim();
            }
            catch
            {
                return "Banner not available";
            }
        }

        private static async Task<string> GetHttpInfoAsync(IPAddress ipAddress, int port)
        {
            try
            {
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                
                var protocol = port == 443 || port == 8443 ? "https" : "http";
                var response = await client.GetAsync($"{protocol}://{ipAddress}:{port}");
                
                var content = await response.Content.ReadAsStringAsync();
                var server = response.Headers.Server?.ToString() ?? "Unknown";
                
                return $"Server: {server}, Content Length: {content.Length}";
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }
        }

        private static void ExtractInfoFromSshBanner(CiscoDevice device, string banner)
        {
            if (banner.Contains("Cisco", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(banner, @"Cisco-(\d+\.[\d\.]+)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    device.IosVersion = match.Groups[1].Value;
                }
            }
        }

        private static void ExtractInfoFromTelnetBanner(CiscoDevice device, string banner)
        {
            // Extract hostname from Telnet banner
            var lines = banner.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                if (line.Contains("User Access Verification"))
                {
                    device.EnabledProtocols.Add("Telnet");
                    break;
                }
            }
        }

        private static void ExtractInfoFromHttpResponse(CiscoDevice device, string httpInfo)
        {
            if (httpInfo.Contains("cisco", StringComparison.OrdinalIgnoreCase))
            {
                device.EnabledProtocols.Add("HTTP Management");
            }
        }

        private static async Task PerformSecurityAssessmentAsync(CiscoDevice device)
        {
            // Check for common security issues
            CheckForDefaultCredentials(device);
            CheckForInsecureProtocols(device);
            CheckForKnownVulnerabilities(device);
            CheckForConfigurationIssues(device);
            
            await Task.CompletedTask;
        }

        private static void CheckForDefaultCredentials(CiscoDevice device)
        {
            if (device.OpenPorts.Contains(23) || device.OpenPorts.Contains(22) || 
                device.OpenPorts.Contains(80) || device.OpenPorts.Contains(443))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Authentication",
                    Severity = "High",
                    Description = "Default credentials may be in use. Common Cisco default credentials include admin/admin, cisco/cisco, admin/cisco.",
                    Recommendation = "Change default credentials immediately. Use strong, unique passwords.",
                    CveId = ""
                });
            }
        }

        private static void CheckForInsecureProtocols(CiscoDevice device)
        {
            if (device.OpenPorts.Contains(23))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "High",
                    Description = "Telnet service is enabled. Telnet transmits credentials and data in plaintext.",
                    Recommendation = "Disable Telnet and use SSH instead. Configure 'no service telnet' and 'transport input ssh'.",
                    CveId = ""
                });
            }

            if (device.OpenPorts.Contains(80))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "Medium",
                    Description = "HTTP management interface is enabled without encryption.",
                    Recommendation = "Use HTTPS only for web management. Configure 'ip http secure-server' and disable 'ip http server'.",
                    CveId = ""
                });
            }

            if (device.OpenPorts.Contains(161))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "Medium",
                    Description = "SNMP service is enabled. May use default community strings.",
                    Recommendation = "Use SNMPv3 with authentication and encryption. Avoid default community strings like 'public' and 'private'.",
                    CveId = ""
                });
            }
        }

        private static void CheckForKnownVulnerabilities(CiscoDevice device)
        {
            // Check for common Cisco vulnerabilities based on detected services
            if (!string.IsNullOrEmpty(device.IosVersion))
            {
                CheckIosVersionVulnerabilities(device);
            }

            if (device.OpenPorts.Contains(80) || device.OpenPorts.Contains(443))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Web Interface",
                    Severity = "Medium",
                    Description = "Web management interface detected. Ensure it's properly secured against common web vulnerabilities.",
                    Recommendation = "Keep firmware updated, use strong authentication, enable HTTPS, and restrict access by IP.",
                    CveId = ""
                });
            }
        }

        private static void CheckIosVersionVulnerabilities(CiscoDevice device)
        {
            // Simplified vulnerability checking based on IOS version patterns
            var version = device.IosVersion.ToLower();
            
            if (version.Contains("15.0") || version.Contains("15.1"))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Firmware",
                    Severity = "High",
                    Description = "Older IOS version detected that may contain known vulnerabilities.",
                    Recommendation = "Upgrade to the latest supported IOS version for your hardware platform.",
                    CveId = "Multiple CVEs"
                });
            }
        }

        private static void CheckForConfigurationIssues(CiscoDevice device)
        {
            device.SecurityFindings.Add(new SecurityFinding
            {
                Category = "Configuration",
                Severity = "Medium",
                Description = "Recommended to verify secure configuration settings.",
                Recommendation = "Review: VTY line security, enable secret, service password-encryption, banner configuration, and access control lists.",
                CveId = ""
            });
        }

        private static async Task AnalyzeConfigurationAsync(CiscoDevice device)
        {
            // This would typically involve connecting to the device and running show commands
            // For security reasons, we'll limit this to passive analysis
            
            device.ConfigurationInfo["Assessment"] = "Passive analysis completed";
            device.ConfigurationInfo["RecommendedCommands"] = "show version, show running-config, show interfaces, show ip route";
            
            await Task.CompletedTask;
        }

        /// <summary>
        /// Generate comprehensive Cisco security report
        /// </summary>
        public static void DisplayCiscoReport(CiscoDevice device)
        {
            var panel = new Panel(GenerateReportContent(device))
                .Header($"[bold yellow]Cisco Device Security Report - {device.IpAddress}[/]")
                .BorderColor(Color.Yellow)
                .Padding(1, 1);

            AnsiConsole.Write(panel);
        }

        private static string GenerateReportContent(CiscoDevice device)
        {
            var content = new StringBuilder();

            // Device Information
            content.AppendLine("[bold cyan]📋 Device Information[/]");
            content.AppendLine($"IP Address: {device.IpAddress}");
            content.AppendLine($"Model: {device.Model ?? "Not detected"}");
            content.AppendLine($"IOS Version: {device.IosVersion ?? "Not detected"}");
            content.AppendLine($"Hostname: {device.Hostname ?? "Not detected"}");
            content.AppendLine();

            // Open Ports
            content.AppendLine("[bold green]🔌 Open Ports[/]");
            if (device.OpenPorts.Count > 0)
            {
                content.AppendLine(string.Join(", ", device.OpenPorts));
            }
            else
            {
                content.AppendLine("No ports detected");
            }
            content.AppendLine();

            // Services
            content.AppendLine("[bold blue]🛠️ Detected Services[/]");
            foreach (var service in device.Services)
            {
                content.AppendLine($"• {service}");
            }
            content.AppendLine();

            // Security Findings
            content.AppendLine("[bold red]🛡️ Security Findings[/]");
            if (device.SecurityFindings.Count > 0)
            {
                foreach (var finding in device.SecurityFindings)
                {
                    var severityColor = finding.Severity.ToLower() switch
                    {
                        "high" => "red",
                        "medium" => "yellow",
                        "low" => "green",
                        _ => "white"
                    };
                    
                    content.AppendLine($"[{severityColor}]• [{finding.Severity}] {finding.Category}: {finding.Description}[/]");
                    content.AppendLine($"  Recommendation: {finding.Recommendation}");
                    if (!string.IsNullOrEmpty(finding.CveId))
                    {
                        content.AppendLine($"  CVE: {finding.CveId}");
                    }
                    content.AppendLine();
                }
            }
            else
            {
                content.AppendLine("No security issues detected in passive scan");
            }

            return content.ToString();
        }

        // ===== BATCH SCANNING METHODS =====

        /// <summary>
        /// Scans Cisco devices from a CSV list containing IP addresses, CIDR networks, and IP ranges
        /// </summary>
        /// <param name="csvContent">CSV content with targets (IPs, CIDRs, ranges)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of Cisco device scan results</returns>
        public static async Task<List<CiscoDevice>> ScanCiscoDevicesFromCsvAsync(string csvContent, CancellationToken cancellationToken = default)
        {
            var targets = ParseCsvTargets(csvContent);
            return await ScanBatchCiscoDevicesAsync(targets, cancellationToken);
        }

        /// <summary>
        /// Scans Cisco devices in a CIDR network range
        /// </summary>
        /// <param name="cidrNotation">CIDR notation (e.g., 192.168.1.0/24)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of Cisco device scan results</returns>
        public static async Task<List<CiscoDevice>> ScanCiscoDevicesCidrAsync(string cidrNotation, CancellationToken cancellationToken = default)
        {
            var targets = new[] { cidrNotation };
            return await ScanBatchCiscoDevicesAsync(targets, cancellationToken);
        }

        /// <summary>
        /// Scans Cisco devices in an IP range
        /// </summary>
        /// <param name="startIp">Starting IP address</param>
        /// <param name="endIp">Ending IP address</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of Cisco device scan results</returns>
        public static async Task<List<CiscoDevice>> ScanCiscoDevicesIpRangeAsync(string startIp, string endIp, CancellationToken cancellationToken = default)
        {
            var rangeTarget = $"{startIp}-{endIp}";
            var targets = new[] { rangeTarget };
            return await ScanBatchCiscoDevicesAsync(targets, cancellationToken);
        }

        /// <summary>
        /// Scans multiple Cisco device targets from a list of target strings (IPs, CIDRs, ranges)
        /// </summary>
        /// <param name="targets">Collection of target strings</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Collection of Cisco device scan results</returns>
        public static async Task<List<CiscoDevice>> ScanBatchCiscoDevicesAsync(IEnumerable<string> targets, CancellationToken cancellationToken = default)
        {
            var allResults = new List<CiscoDevice>();
            var expandedIps = ExpandTargetsToIps(targets).Distinct().ToList();
            
            // Skip interactive prompts in test environment
            if (!Discovery.Core.Utilities.TestEnvironmentDetector.IsTestEnvironment && expandedIps.Count > 50)
            {
                var confirm = AnsiConsole.Confirm($"About to scan {expandedIps.Count} IP addresses for Cisco devices. This may take a while. Continue?");
                if (!confirm)
                {
                    AnsiConsole.MarkupLine("[yellow]Cisco device scan cancelled by user.[/]");
                    return allResults;
                }
            }

            AnsiConsole.MarkupLine($"[bold cyan]🏭 Starting batch Cisco device scan on {expandedIps.Count} targets...[/]");

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
                    var task = ctx.AddTask("[yellow]Scanning for Cisco devices...[/]", maxValue: expandedIps.Count);
                    
                    // Use a semaphore to limit concurrent scans
                    using var semaphore = new SemaphoreSlim(Math.Min(15, expandedIps.Count), Math.Min(15, expandedIps.Count));
                    
                    var tasks = expandedIps.Select(async ip =>
                    {
                        await semaphore.WaitAsync(cancellationToken);
                        try
                        {
                            if (IPAddress.TryParse(ip, out var ipAddress))
                            {
                                var result = await ScanCiscoDeviceAsync(ipAddress);
                                task.Increment(1);
                                return result;
                            }
                            task.Increment(1);
                            return null;
                        }
                        catch (Exception ex)
                        {
                            // Log error but continue with other IPs
                            if (!Discovery.Core.Utilities.TestEnvironmentDetector.IsTestEnvironment)
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
                        if (result != null && result.OpenPorts.Any())
                            allResults.Add(result);
                    }
                });

            var ciscoDevicesFound = allResults.Where(r => !string.IsNullOrEmpty(r.Model) || r.OpenPorts.Any()).ToList();
            
            if (!Discovery.Core.Utilities.TestEnvironmentDetector.IsTestEnvironment)
            {
                AnsiConsole.MarkupLine($"[bold green]✅ Cisco device scan completed: {ciscoDevicesFound.Count} devices found out of {expandedIps.Count} targets[/]");
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
            // Check if it's an IP range
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