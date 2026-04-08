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
    /// MikroTik RouterOS specific scanning and security assessment tools
    /// </summary>
    public static class MikroTikScanner
    {
        public class MikroTikDevice
        {
            public IPAddress IpAddress { get; set; } = IPAddress.None;
            public string Model { get; set; } = "";
            public string RouterOsVersion { get; set; } = "";
            public string Architecture { get; set; } = "";
            public string BoardName { get; set; } = "";
            public string Identity { get; set; } = "";
            public List<int> OpenPorts { get; set; } = new();
            public List<string> Services { get; set; } = new();
            public List<SecurityFinding> SecurityFindings { get; set; } = new();
            public Dictionary<string, string> ApiInfo { get; set; } = new();
            public bool WinboxEnabled { get; set; }
            public bool ApiEnabled { get; set; }
            public bool WebfigEnabled { get; set; }
            public List<string> DiscoveredInterfaces { get; set; } = new();
            public Dictionary<string, string> SystemInfo { get; set; } = new();
        }

        public class SecurityFinding
        {
            public string Category { get; set; } = "";
            public string Severity { get; set; } = "";
            public string Description { get; set; } = "";
            public string Recommendation { get; set; } = "";
            public string CveId { get; set; } = "";
        }

        private static readonly Dictionary<string, List<string>> MikroTikDefaultCredentials = new()
        {
            ["admin"] = new List<string> { "", "admin", "MikroTik", "123456" },
            ["user"] = new List<string> { "", "password" },
            ["guest"] = new List<string> { "", "guest" }
        };

        private static readonly int[] MikroTikCommonPorts = {
            21,    // FTP
            22,    // SSH
            23,    // Telnet
            53,    // DNS
            80,    // HTTP (Webfig)
            443,   // HTTPS
            2000,  // Bandwidth Test
            8080,  // HTTP Proxy
            8291,  // Winbox
            8728,  // API
            8729,  // API-SSL
            5678   // MikroTik Neighbor Discovery
        };

        /// <summary>
        /// Comprehensive MikroTik RouterOS device scan and security assessment
        /// </summary>
        public static async Task<MikroTikDevice> ScanMikroTikDeviceAsync(IPAddress ipAddress)
        {
            var device = new MikroTikDevice { IpAddress = ipAddress };

            AnsiConsole.MarkupLine($"[cyan]🔍 Scanning MikroTik RouterOS device at {ipAddress}...[/]");

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
                    var task3 = ctx.AddTask("[green]RouterOS analysis...[/]");
                    var task4 = ctx.AddTask("[red]Security assessment...[/]");

                    // Port scanning
                    await ScanPortsAsync(device);
                    task1.Value = 100;

                    // Service detection
                    await DetectServicesAsync(device);
                    task2.Value = 100;

                    // RouterOS specific analysis
                    await AnalyzeRouterOsAsync(device);
                    task3.Value = 100;

                    // Security assessment
                    await PerformSecurityAssessmentAsync(device);
                    task4.Value = 100;
                });

            return device;
        }

        private static async Task ScanPortsAsync(MikroTikDevice device)
        {
            var tasks = MikroTikCommonPorts.Select(async port =>
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

        private static async Task DetectServicesAsync(MikroTikDevice device)
        {
            foreach (var port in device.OpenPorts)
            {
                try
                {
                    switch (port)
                    {
                        case 8291:
                            device.WinboxEnabled = true;
                            device.Services.Add("Winbox Management Interface");
                            await AnalyzeWinboxAsync(device);
                            break;

                        case 8728:
                            device.ApiEnabled = true;
                            device.Services.Add("RouterOS API");
                            await AnalyzeApiAsync(device, false);
                            break;

                        case 8729:
                            device.ApiEnabled = true;
                            device.Services.Add("RouterOS API-SSL");
                            await AnalyzeApiAsync(device, true);
                            break;

                        case 80:
                        case 443:
                            device.WebfigEnabled = true;
                            var httpInfo = await GetHttpInfoAsync(device.IpAddress, port);
                            device.Services.Add($"Webfig ({port}): {httpInfo}");
                            ExtractInfoFromWebfig(device, httpInfo);
                            break;

                        case 22:
                            var sshBanner = await GetSshBannerAsync(device.IpAddress);
                            device.Services.Add($"SSH: {sshBanner}");
                            ExtractInfoFromSshBanner(device, sshBanner);
                            break;

                        case 23:
                            var telnetBanner = await GetTelnetBannerAsync(device.IpAddress);
                            device.Services.Add($"Telnet: {telnetBanner}");
                            break;

                        case 2000:
                            device.Services.Add("Bandwidth Test Server");
                            break;

                        case 5678:
                            device.Services.Add("MikroTik Neighbor Discovery Protocol");
                            break;

                        default:
                            device.Services.Add($"Port {port}: Service detected");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    device.Services.Add($"Port {port}: Error - {ex.Message}");
                }
            }
        }

        private static async Task AnalyzeWinboxAsync(MikroTikDevice device)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(device.IpAddress, 8291);
                
                // Winbox protocol analysis (simplified)
                // In a real implementation, you would implement the Winbox protocol
                device.ApiInfo["Winbox"] = "Detected - Protocol analysis limited for security";
            }
            catch
            {
                device.ApiInfo["Winbox"] = "Connection failed";
            }
        }

        private static async Task AnalyzeApiAsync(MikroTikDevice device, bool ssl)
        {
            try
            {
                var port = ssl ? 8729 : 8728;
                using var client = new TcpClient();
                await client.ConnectAsync(device.IpAddress, port);
                
                // RouterOS API protocol analysis (simplified)
                device.ApiInfo[ssl ? "API-SSL" : "API"] = "Detected - Authentication required";
            }
            catch
            {
                device.ApiInfo[ssl ? "API-SSL" : "API"] = "Connection failed";
            }
        }

        private static async Task<string> GetHttpInfoAsync(IPAddress ipAddress, int port)
        {
            try
            {
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                
                var protocol = port == 443 ? "https" : "http";
                var response = await client.GetAsync($"{protocol}://{ipAddress}:{port}");
                
                var content = await response.Content.ReadAsStringAsync();
                var server = response.Headers.Server?.ToString() ?? "Unknown";
                
                // Look for RouterOS specific indicators
                if (content.Contains("RouterOS", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("MikroTik", StringComparison.OrdinalIgnoreCase))
                {
                    return "RouterOS Webfig Interface";
                }
                
                return $"HTTP Server: {server}";
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
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

        private static void ExtractInfoFromWebfig(MikroTikDevice device, string httpInfo)
        {
            if (httpInfo.Contains("RouterOS", StringComparison.OrdinalIgnoreCase))
            {
                device.SystemInfo["WebInterface"] = "RouterOS Webfig";
            }
        }

        private static void ExtractInfoFromSshBanner(MikroTikDevice device, string banner)
        {
            if (banner.Contains("ROSSSH", StringComparison.OrdinalIgnoreCase))
            {
                device.SystemInfo["SSH"] = "RouterOS SSH";
                
                // Try to extract version from banner
                var match = Regex.Match(banner, @"(\d+\.\d+(?:\.\d+)?)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    device.RouterOsVersion = match.Groups[1].Value;
                }
            }
        }

        private static async Task AnalyzeRouterOsAsync(MikroTikDevice device)
        {
            // RouterOS specific analysis
            if (device.WinboxEnabled)
            {
                device.SystemInfo["Management"] = "Winbox enabled";
            }
            
            if (device.ApiEnabled)
            {
                device.SystemInfo["API"] = "RouterOS API enabled";
            }
            
            if (device.WebfigEnabled)
            {
                device.SystemInfo["WebManagement"] = "Webfig enabled";
            }

            await Task.CompletedTask;
        }

        private static async Task PerformSecurityAssessmentAsync(MikroTikDevice device)
        {
            CheckForDefaultCredentials(device);
            CheckForInsecureServices(device);
            CheckForKnownVulnerabilities(device);
            CheckForConfigurationIssues(device);
            
            await Task.CompletedTask;
        }

        private static void CheckForDefaultCredentials(MikroTikDevice device)
        {
            if (device.WinboxEnabled || device.WebfigEnabled || device.ApiEnabled ||
                device.OpenPorts.Contains(22) || device.OpenPorts.Contains(23))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Authentication",
                    Severity = "High",
                    Description = "Management interfaces detected. Default credentials may be in use (admin with blank password).",
                    Recommendation = "Change default admin password immediately. Consider disabling unused management interfaces.",
                    CveId = ""
                });
            }
        }

        private static void CheckForInsecureServices(MikroTikDevice device)
        {
            if (device.OpenPorts.Contains(23))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "High",
                    Description = "Telnet service is enabled, transmitting credentials in plaintext.",
                    Recommendation = "Disable Telnet service and use SSH instead. Use '/ip service disable telnet'.",
                    CveId = ""
                });
            }

            if (device.OpenPorts.Contains(8291))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "Medium",
                    Description = "Winbox service is enabled. Ensure access is restricted and use strong authentication.",
                    Recommendation = "Restrict Winbox access by IP address and use strong passwords. Consider VPN access only.",
                    CveId = ""
                });
            }

            if (device.OpenPorts.Contains(8728))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "Medium",
                    Description = "RouterOS API service enabled without encryption.",
                    Recommendation = "Use API-SSL (port 8729) instead of unencrypted API. Disable unencrypted API if not needed.",
                    CveId = ""
                });
            }

            if (device.OpenPorts.Contains(80))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "Medium",
                    Description = "HTTP web interface (Webfig) enabled without encryption.",
                    Recommendation = "Use HTTPS only for web management. Disable HTTP service if not needed.",
                    CveId = ""
                });
            }
        }

        private static void CheckForKnownVulnerabilities(MikroTikDevice device)
        {
            if (!string.IsNullOrEmpty(device.RouterOsVersion))
            {
                CheckRouterOsVersionVulnerabilities(device);
            }

            // Check for common MikroTik vulnerabilities
            if (device.WinboxEnabled)
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Known Vulnerabilities",
                    Severity = "High",
                    Description = "Winbox interface detected. Historical vulnerabilities include CVE-2018-14847 (credential disclosure).",
                    Recommendation = "Ensure RouterOS is updated to latest version. Review firewall rules to restrict Winbox access.",
                    CveId = "CVE-2018-14847"
                });
            }
        }

        private static void CheckRouterOsVersionVulnerabilities(MikroTikDevice device)
        {
            var version = device.RouterOsVersion;
            
            // Check for known vulnerable versions
            if (IsVersionOlderThan(version, "6.40.4"))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Firmware",
                    Severity = "Critical",
                    Description = "RouterOS version is vulnerable to CVE-2018-14847 (Winbox credential disclosure).",
                    Recommendation = "Immediately upgrade RouterOS to version 6.40.4 or later.",
                    CveId = "CVE-2018-14847"
                });
            }
            
            if (IsVersionOlderThan(version, "6.44.6"))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Firmware",
                    Severity = "High",
                    Description = "RouterOS version may contain known vulnerabilities. Multiple CVEs affect older versions.",
                    Recommendation = "Upgrade to RouterOS 6.44.6 or later for security fixes.",
                    CveId = "Multiple CVEs"
                });
            }
        }

        private static bool IsVersionOlderThan(string currentVersion, string compareVersion)
        {
            try
            {
                var current = Version.Parse(currentVersion);
                var compare = Version.Parse(compareVersion);
                return current < compare;
            }
            catch
            {
                return false; // Can't determine, assume false
            }
        }

        private static void CheckForConfigurationIssues(MikroTikDevice device)
        {
            device.SecurityFindings.Add(new SecurityFinding
            {
                Category = "Configuration",
                Severity = "Medium",
                Description = "Review RouterOS security configuration settings.",
                Recommendation = "Check: IP services restrictions, user permissions, firewall rules, neighbor discovery settings, and MAC server settings.",
                CveId = ""
            });

            if (device.OpenPorts.Contains(5678))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Information Disclosure",
                    Severity = "Low",
                    Description = "MikroTik Neighbor Discovery Protocol is enabled, which may leak network topology information.",
                    Recommendation = "Consider disabling neighbor discovery if not needed: '/ip neighbor discovery-settings set discover-interface-list=none'.",
                    CveId = ""
                });
            }
        }

        /// <summary>
        /// Generate comprehensive MikroTik security report
        /// </summary>
        public static void DisplayMikroTikReport(MikroTikDevice device)
        {
            var panel = new Panel(GenerateReportContent(device))
                .Header($"[bold yellow]MikroTik RouterOS Security Report - {device.IpAddress}[/]")
                .BorderColor(Color.Yellow)
                .Padding(1, 1);

            AnsiConsole.Write(panel);
        }

        private static string GenerateReportContent(MikroTikDevice device)
        {
            var content = new StringBuilder();

            // Device Information
            content.AppendLine("[bold cyan]📋 Device Information[/]");
            content.AppendLine($"IP Address: {device.IpAddress}");
            content.AppendLine($"Model: {device.Model ?? "Not detected"}");
            content.AppendLine($"RouterOS Version: {device.RouterOsVersion ?? "Not detected"}");
            content.AppendLine($"Architecture: {device.Architecture ?? "Not detected"}");
            content.AppendLine($"Identity: {device.Identity ?? "Not detected"}");
            content.AppendLine();

            // Management Interfaces
            content.AppendLine("[bold green]🔌 Management Interfaces[/]");
            if (device.WinboxEnabled) content.AppendLine("• Winbox (Port 8291)");
            if (device.ApiEnabled) content.AppendLine("• RouterOS API");
            if (device.WebfigEnabled) content.AppendLine("• Webfig HTTP Interface");
            if (device.OpenPorts.Contains(22)) content.AppendLine("• SSH (Port 22)");
            if (device.OpenPorts.Contains(23)) content.AppendLine("• Telnet (Port 23)");
            content.AppendLine();

            // Open Ports
            content.AppendLine("[bold blue]🔌 Open Ports[/]");
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
            content.AppendLine("[bold purple]🛠️ Detected Services[/]");
            foreach (var service in device.Services)
            {
                content.AppendLine($"• {service}");
            }
            content.AppendLine();

            // System Information
            content.AppendLine("[bold cyan]ℹ️ System Information[/]");
            foreach (var info in device.SystemInfo)
            {
                content.AppendLine($"• {info.Key}: {info.Value}");
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
                        "critical" => "red",
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
    }
}