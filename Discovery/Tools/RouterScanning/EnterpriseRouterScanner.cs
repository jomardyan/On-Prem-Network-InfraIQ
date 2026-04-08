using System;
using System.Collections.Generic;
using System.Linq;
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
    /// Enterprise router and firewall scanner for Juniper, Fortinet, Palo Alto, SonicWall, etc.
    /// </summary>
    public static class EnterpriseRouterScanner
    {
        public class EnterpriseDevice
        {
            public IPAddress IpAddress { get; set; } = IPAddress.None;
            public string Brand { get; set; } = "";
            public string Model { get; set; } = "";
            public string FirmwareVersion { get; set; } = "";
            public string DeviceType { get; set; } = "";
            public List<int> OpenPorts { get; set; } = new();
            public List<string> Services { get; set; } = new();
            public List<SecurityFinding> SecurityFindings { get; set; } = new();
            public Dictionary<string, string> ManagementInterfaces { get; set; } = new();
            public List<string> SupportedProtocols { get; set; } = new();
            public Dictionary<string, string> CertificateInfo { get; set; } = new();
        }

        public class SecurityFinding
        {
            public string Category { get; set; } = "";
            public string Severity { get; set; } = "";
            public string Description { get; set; } = "";
            public string Recommendation { get; set; } = "";
            public string CveId { get; set; } = "";
        }

        private static readonly Dictionary<string, EnterpriseSignature> EnterpriseSignatures = new()
        {
            ["Juniper"] = new EnterpriseSignature
            {
                HttpTitlePatterns = new[] { "Juniper", "JUNOS", "J-Web", "EX Series", "SRX Series", "MX Series" },
                SshBannerPatterns = new[] { "Juniper" },
                HttpServerHeaders = new[] { "lighttpd", "Juniper" },
                CommonPorts = new[] { 22, 80, 443, 830, 3000, 8080 },
                DeviceTypes = new[] { "Router", "Switch", "Firewall" }
            },
            ["Fortinet"] = new EnterpriseSignature
            {
                HttpTitlePatterns = new[] { "FortiGate", "Fortinet", "FortiManager", "FortiAnalyzer" },
                SshBannerPatterns = new[] { "FortiSSH" },
                HttpServerHeaders = new[] { "AwsomeHttpd", "FortiGate" },
                CommonPorts = new[] { 22, 80, 443, 541, 8008, 8080, 8443, 10443 },
                DeviceTypes = new[] { "Firewall", "UTM" }
            },
            ["Palo Alto"] = new EnterpriseSignature
            {
                HttpTitlePatterns = new[] { "Palo Alto", "PAN-OS", "GlobalProtect" },
                SshBannerPatterns = new[] { "PAN-OS" },
                HttpServerHeaders = new[] { "PAN-Webserver" },
                CommonPorts = new[] { 22, 80, 443, 3978, 4433 },
                DeviceTypes = new[] { "Firewall", "NGFW" }
            },
            ["SonicWall"] = new EnterpriseSignature
            {
                HttpTitlePatterns = new[] { "SonicWall", "SonicOS" },
                SshBannerPatterns = new[] { "SonicWall" },
                HttpServerHeaders = new[] { "SonicWall" },
                CommonPorts = new[] { 22, 80, 443, 4200 },
                DeviceTypes = new[] { "Firewall", "UTM" }
            },
            ["Huawei"] = new EnterpriseSignature
            {
                HttpTitlePatterns = new[] { "Huawei", "VRP", "eNSP" },
                SshBannerPatterns = new[] { "VRP", "Huawei" },
                HttpServerHeaders = new[] { "VRP-Webserver" },
                CommonPorts = new[] { 22, 23, 80, 443, 161, 8080 },
                DeviceTypes = new[] { "Router", "Switch", "Firewall" }
            }
        };

        private class EnterpriseSignature
        {
            public string[] HttpTitlePatterns { get; set; } = Array.Empty<string>();
            public string[] SshBannerPatterns { get; set; } = Array.Empty<string>();
            public string[] HttpServerHeaders { get; set; } = Array.Empty<string>();
            public int[] CommonPorts { get; set; } = Array.Empty<int>();
            public string[] DeviceTypes { get; set; } = Array.Empty<string>();
        }

        /// <summary>
        /// Scan for enterprise network equipment
        /// </summary>
        public static async Task<EnterpriseDevice> ScanEnterpriseDeviceAsync(IPAddress ipAddress)
        {
            var device = new EnterpriseDevice { IpAddress = ipAddress };

            AnsiConsole.MarkupLine($"[cyan]🔍 Scanning enterprise device at {ipAddress}...[/]");

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
                    var task3 = ctx.AddTask("[green]Brand identification...[/]");
                    var task4 = ctx.AddTask("[red]Security assessment...[/]");

                    // Port scanning
                    await ScanPortsAsync(device);
                    task1.Value = 100;

                    // Service detection
                    await DetectServicesAsync(device);
                    task2.Value = 100;

                    // Brand identification
                    await IdentifyBrandAsync(device);
                    task3.Value = 100;

                    // Security assessment
                    await PerformSecurityAssessmentAsync(device);
                    task4.Value = 100;
                });

            return device;
        }

        private static async Task ScanPortsAsync(EnterpriseDevice device)
        {
            var allPorts = EnterpriseSignatures.Values
                .SelectMany(s => s.CommonPorts)
                .Distinct()
                .ToArray();

            var tasks = allPorts.Select(async port =>
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

        private static async Task DetectServicesAsync(EnterpriseDevice device)
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
                            device.ManagementInterfaces["SSH"] = $"ssh://{device.IpAddress}:22";
                            break;

                        case 80:
                        case 443:
                        case 8080:
                        case 8443:
                        case 10443:
                            var httpInfo = await GetHttpInfoAsync(device.IpAddress, port);
                            device.Services.Add($"HTTP({port}): {httpInfo}");
                            var protocol = (port == 443 || port == 8443 || port == 10443) ? "https" : "http";
                            device.ManagementInterfaces[$"Web-{port}"] = $"{protocol}://{device.IpAddress}:{port}";
                            break;

                        case 830:
                            device.Services.Add("NETCONF");
                            device.SupportedProtocols.Add("NETCONF");
                            break;

                        case 161:
                            device.Services.Add("SNMP");
                            device.SupportedProtocols.Add("SNMP");
                            break;

                        case 541:
                            device.Services.Add("FortiGate SSL VPN");
                            break;

                        case 4200:
                            device.Services.Add("SonicWall Management");
                            break;

                        case 3978:
                            device.Services.Add("Palo Alto GlobalProtect");
                            break;

                        default:
                            device.Services.Add($"Port {port}: Unknown service");
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

        private static async Task<string> GetHttpInfoAsync(IPAddress ipAddress, int port)
        {
            try
            {
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                
                var protocol = (port == 443 || port == 8443 || port == 10443) ? "https" : "http";
                var response = await client.GetAsync($"{protocol}://{ipAddress}:{port}");
                
                var content = await response.Content.ReadAsStringAsync();
                var server = response.Headers.Server?.ToString() ?? "Unknown";
                
                return $"Server: {server}, Title: {ExtractTitle(content)}";
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }
        }

        private static string ExtractTitle(string html)
        {
            var match = Regex.Match(html, @"<title[^>]*>([^<]+)</title>", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value.Trim() : "Unknown";
        }

        private static async Task IdentifyBrandAsync(EnterpriseDevice device)
        {
            foreach (var kvp in EnterpriseSignatures)
            {
                var brand = kvp.Key;
                var signature = kvp.Value;
                var confidence = 0;

                // Check services for brand indicators
                foreach (var service in device.Services)
                {
                    foreach (var pattern in signature.HttpTitlePatterns.Concat(signature.SshBannerPatterns))
                    {
                        if (service.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            confidence += 20;
                        }
                    }
                }

                // Check port patterns
                var matchedPorts = signature.CommonPorts.Intersect(device.OpenPorts).Count();
                confidence += matchedPorts * 5;

                if (confidence >= 20)
                {
                    device.Brand = brand;
                    device.DeviceType = signature.DeviceTypes.FirstOrDefault() ?? "Unknown";
                    break;
                }
            }

            await Task.CompletedTask;
        }

        private static async Task PerformSecurityAssessmentAsync(EnterpriseDevice device)
        {
            CheckForInsecureProtocols(device);
            CheckForDefaultPorts(device);
            CheckForCertificateIssues(device);
            CheckBrandSpecificVulnerabilities(device);

            await Task.CompletedTask;
        }

        private static void CheckForInsecureProtocols(EnterpriseDevice device)
        {
            if (device.OpenPorts.Contains(23))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "High",
                    Description = "Telnet service enabled - credentials transmitted in plaintext",
                    Recommendation = "Disable Telnet and use SSH for remote management",
                    CveId = ""
                });
            }

            if (device.OpenPorts.Contains(80))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "Medium",
                    Description = "HTTP management interface without encryption",
                    Recommendation = "Configure HTTPS-only access for web management",
                    CveId = ""
                });
            }

            if (device.OpenPorts.Contains(161))
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Protocol Security",
                    Severity = "Medium",
                    Description = "SNMP service detected - may use weak community strings",
                    Recommendation = "Use SNMPv3 with strong authentication and encryption",
                    CveId = ""
                });
            }
        }

        private static void CheckForDefaultPorts(EnterpriseDevice device)
        {
            var riskPorts = new Dictionary<int, string>
            {
                [80] = "Default HTTP management port",
                [8080] = "Alternative HTTP management port",
                [443] = "HTTPS management (ensure proper certificates)",
                [22] = "SSH access (ensure key-based authentication)"
            };

            foreach (var kvp in riskPorts)
            {
                if (device.OpenPorts.Contains(kvp.Key))
                {
                    device.SecurityFindings.Add(new SecurityFinding
                    {
                        Category = "Service Configuration",
                        Severity = "Low",
                        Description = $"Standard management port {kvp.Key} in use: {kvp.Value}",
                        Recommendation = "Consider using non-standard ports and implement access restrictions",
                        CveId = ""
                    });
                }
            }
        }

        private static void CheckForCertificateIssues(EnterpriseDevice device)
        {
            var httpsPorts = device.OpenPorts.Where(p => p == 443 || p == 8443 || p == 10443);
            
            if (httpsPorts.Any())
            {
                device.SecurityFindings.Add(new SecurityFinding
                {
                    Category = "Certificate Security",
                    Severity = "Medium",
                    Description = "HTTPS services detected - verify certificate validity and strength",
                    Recommendation = "Ensure valid certificates, strong cipher suites, and disable deprecated protocols",
                    CveId = ""
                });
            }
        }

        private static void CheckBrandSpecificVulnerabilities(EnterpriseDevice device)
        {
            switch (device.Brand.ToLower())
            {
                case "fortinet":
                    device.SecurityFindings.Add(new SecurityFinding
                    {
                        Category = "Brand-Specific",
                        Severity = "High",
                        Description = "FortiGate devices have had multiple critical vulnerabilities",
                        Recommendation = "Ensure latest firmware, review CVE-2022-40684, CVE-2023-27997",
                        CveId = "CVE-2022-40684, CVE-2023-27997"
                    });
                    break;

                case "palo alto":
                    device.SecurityFindings.Add(new SecurityFinding
                    {
                        Category = "Brand-Specific",
                        Severity = "Medium",
                        Description = "Palo Alto devices - verify GlobalProtect security",
                        Recommendation = "Review CVE-2022-0028, ensure proper GlobalProtect configuration",
                        CveId = "CVE-2022-0028"
                    });
                    break;

                case "juniper":
                    device.SecurityFindings.Add(new SecurityFinding
                    {
                        Category = "Brand-Specific",
                        Severity = "Medium",
                        Description = "Juniper devices - review JUNOS security advisories",
                        Recommendation = "Ensure latest JUNOS version, review recent security advisories",
                        CveId = ""
                    });
                    break;

                case "sonicwall":
                    device.SecurityFindings.Add(new SecurityFinding
                    {
                        Category = "Brand-Specific",
                        Severity = "High",
                        Description = "SonicWall devices have had authentication bypass vulnerabilities",
                        Recommendation = "Verify latest firmware, review CVE-2021-20016, CVE-2021-20028",
                        CveId = "CVE-2021-20016, CVE-2021-20028"
                    });
                    break;
            }
        }

        /// <summary>
        /// Display comprehensive enterprise device report
        /// </summary>
        public static void DisplayEnterpriseReport(EnterpriseDevice device)
        {
            var panel = new Panel(GenerateReportContent(device))
                .Header($"[bold yellow]Enterprise Device Security Report - {device.IpAddress}[/]")
                .BorderColor(Color.Yellow)
                .Padding(1, 1);

            AnsiConsole.Write(panel);
        }

        private static string GenerateReportContent(EnterpriseDevice device)
        {
            var content = new StringBuilder();

            // Device Information
            content.AppendLine("[bold cyan]📋 Device Information[/]");
            content.AppendLine($"IP Address: {device.IpAddress}");
            content.AppendLine($"Brand: {device.Brand ?? "Unknown"}");
            content.AppendLine($"Model: {device.Model ?? "Not detected"}");
            content.AppendLine($"Device Type: {device.DeviceType ?? "Unknown"}");
            content.AppendLine($"Firmware: {device.FirmwareVersion ?? "Not detected"}");
            content.AppendLine();

            // Management Interfaces
            content.AppendLine("[bold green]🌐 Management Interfaces[/]");
            foreach (var interface_ in device.ManagementInterfaces)
            {
                content.AppendLine($"• {interface_.Key}: {interface_.Value}");
            }
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

            // Supported Protocols
            content.AppendLine("[bold cyan]📡 Supported Protocols[/]");
            foreach (var protocol in device.SupportedProtocols)
            {
                content.AppendLine($"• {protocol}");
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