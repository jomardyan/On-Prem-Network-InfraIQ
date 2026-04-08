using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Linq;
using Spectre.Console;

namespace Discovery.Tools.Advanced
{
    /// <summary>
    /// Advanced Red Team tools for penetration testing and security assessment
    /// </summary>
    public static class RedTeamTools
    {
        /// <summary>
        /// OSINT (Open Source Intelligence) gathering tools
        /// </summary>
        public static class OsintGathering
        {
            /// <summary>
            /// Gathers information about a domain from various sources
            /// </summary>
            public static async Task<OsintReport> GatherDomainIntelligence(string domain)
            {
                var report = new OsintReport { Domain = domain };
                
                AnsiConsole.MarkupLine($"[bold cyan]🕵️ Gathering OSINT for {domain}[/]");
                AnsiConsole.WriteLine();

                // DNS enumeration
                await GatherDnsIntelligence(domain, report);
                
                // Network infrastructure analysis
                await AnalyzeNetworkInfrastructure(domain, report);
                
                // Security headers analysis
                await AnalyzeSecurityHeaders(domain, report);
                
                // Technology fingerprinting
                await FingerprintTechnologies(domain, report);
                
                return report;
            }

            private static async Task GatherDnsIntelligence(string domain, OsintReport report)
            {
                AnsiConsole.MarkupLine("[yellow]🌐 Gathering DNS intelligence...[/]");
                
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(domain);
                    report.IpAddresses = hostEntry.AddressList.Select(ip => ip.ToString()).ToList();
                    
                    foreach (var ip in hostEntry.AddressList)
                    {
                        // Check if IP is in known cloud provider ranges
                        var cloudProvider = IdentifyCloudProvider(ip);
                        if (!string.IsNullOrEmpty(cloudProvider))
                        {
                            report.CloudProviders.Add(cloudProvider);
                        }
                        
                        // Geolocation (basic implementation)
                        var location = EstimateGeolocation(ip);
                        if (!string.IsNullOrEmpty(location))
                        {
                            report.GeographicLocations.Add($"{ip} -> {location}");
                        }
                    }
                    
                    AnsiConsole.MarkupLine($"[green]✅ Found {report.IpAddresses.Count} IP addresses[/]");
                }
                catch (Exception ex)
                {
                    report.Errors.Add($"DNS resolution failed: {ex.Message}");
                }
            }

            private static async Task AnalyzeNetworkInfrastructure(string domain, OsintReport report)
            {
                AnsiConsole.MarkupLine("[yellow]🏗️ Analyzing network infrastructure...[/]");
                
                // Port scanning for common services
                var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900 };
                
                foreach (var ipStr in report.IpAddresses)
                {
                    if (IPAddress.TryParse(ipStr, out var ip))
                    {
                        var openPorts = new List<int>();
                        
                        foreach (var port in commonPorts)
                        {
                            try
                            {
                                using var client = new TcpClient();
                                var connectTask = client.ConnectAsync(ip, port);
                                var timeoutTask = Task.Delay(2000);
                                
                                if (await Task.WhenAny(connectTask, timeoutTask) == connectTask && client.Connected)
                                {
                                    openPorts.Add(port);
                                }
                            }
                            catch
                            {
                                // Port closed
                            }
                        }
                        
                        if (openPorts.Any())
                        {
                            report.OpenPorts[ipStr] = openPorts;
                            AnsiConsole.MarkupLine($"[green]✅ {ipStr}: {openPorts.Count} open ports[/]");
                        }
                    }
                }
            }

            private static async Task AnalyzeSecurityHeaders(string domain, OsintReport report)
            {
                AnsiConsole.MarkupLine("[yellow]🛡️ Analyzing security headers...[/]");
                
                try
                {
                    using var httpClient = new HttpClient();
                    httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Security Scanner)");
                    
                    var response = await httpClient.GetAsync($"https://{domain}");
                    
                    var securityHeaders = new[]
                    {
                        "Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                        "X-XSS-Protection",
                        "Referrer-Policy",
                        "Feature-Policy",
                        "Permissions-Policy"
                    };

                    foreach (var header in securityHeaders)
                    {
                        if (response.Headers.Contains(header) || response.Content.Headers.Contains(header))
                        {
                            report.SecurityHeaders.Add(header);
                        }
                        else
                        {
                            report.MissingSecurityHeaders.Add(header);
                        }
                    }
                    
                    AnsiConsole.MarkupLine($"[green]✅ Security headers analysis complete[/]");
                }
                catch (Exception ex)
                {
                    report.Errors.Add($"Security headers analysis failed: {ex.Message}");
                }
            }

            private static async Task FingerprintTechnologies(string domain, OsintReport report)
            {
                AnsiConsole.MarkupLine("[yellow]🔍 Fingerprinting technologies...[/]");
                
                try
                {
                    using var httpClient = new HttpClient();
                    httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Technology Scanner)");
                    
                    var response = await httpClient.GetAsync($"https://{domain}");
                    var content = await response.Content.ReadAsStringAsync();
                    
                    // Server header analysis
                    if (response.Headers.Server != null)
                    {
                        report.Technologies.Add($"Server: {response.Headers.Server}");
                    }
                    
                    // Technology fingerprinting based on headers and content
                    var techFingerprints = new Dictionary<string, string[]>
                    {
                        { "WordPress", new[] { "wp-content", "wp-includes", "/wp-admin" } },
                        { "Drupal", new[] { "Drupal.settings", "/sites/default", "drupal.js" } },
                        { "Joomla", new[] { "/components/com_", "Joomla!", "/templates/" } },
                        { "ASP.NET", new[] { "__VIEWSTATE", ".aspx", "WebResource.axd" } },
                        { "PHP", new[] { "Set-Cookie: PHPSESSID", ".php", "X-Powered-By: PHP" } },
                        { "Apache", new[] { "Server: Apache", "Apache/" } },
                        { "Nginx", new[] { "Server: nginx", "nginx/" } },
                        { "IIS", new[] { "Server: Microsoft-IIS", "X-Powered-By: ASP.NET" } }
                    };

                    foreach (var tech in techFingerprints)
                    {
                        var responseText = response.ToString() + content;
                        if (tech.Value.Any(pattern => responseText.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                        {
                            report.Technologies.Add(tech.Key);
                        }
                    }
                    
                    AnsiConsole.MarkupLine($"[green]✅ Technology fingerprinting complete[/]");
                }
                catch (Exception ex)
                {
                    report.Errors.Add($"Technology fingerprinting failed: {ex.Message}");
                }
            }

            private static string IdentifyCloudProvider(IPAddress ip)
            {
                // Basic cloud provider identification based on IP ranges
                // This is a simplified version - real implementation would use comprehensive IP range databases
                
                var ipBytes = ip.GetAddressBytes();
                if (ipBytes.Length != 4) return string.Empty;
                
                var firstOctet = ipBytes[0];
                var secondOctet = ipBytes[1];
                
                // AWS ranges (examples)
                if ((firstOctet == 52 || firstOctet == 54 || firstOctet == 34) ||
                    (firstOctet == 3 && secondOctet >= 208))
                {
                    return "Amazon Web Services (AWS)";
                }
                
                // Azure ranges (examples)
                if (firstOctet == 20 || firstOctet == 40 || 
                    (firstOctet == 104 && secondOctet >= 40 && secondOctet <= 47))
                {
                    return "Microsoft Azure";
                }
                
                // Google Cloud ranges (examples)
                if ((firstOctet == 35 && secondOctet >= 184 && secondOctet <= 191) ||
                    (firstOctet == 130 && secondOctet >= 211))
                {
                    return "Google Cloud Platform";
                }
                
                // Cloudflare ranges (examples)
                if (firstOctet == 104 && (secondOctet == 16 || secondOctet == 17 || secondOctet == 18))
                {
                    return "Cloudflare";
                }
                
                return string.Empty;
            }

            private static string EstimateGeolocation(IPAddress ip)
            {
                // Basic geolocation estimation
                // In a real implementation, this would use a geolocation service or database
                
                var ipBytes = ip.GetAddressBytes();
                if (ipBytes.Length != 4) return string.Empty;
                
                // This is a very basic example - real geolocation requires external services
                var firstOctet = ipBytes[0];
                
                return firstOctet switch
                {
                    >= 1 and <= 126 => "North America (estimated)",
                    >= 128 and <= 191 => "Europe/Asia (estimated)",
                    >= 192 and <= 223 => "Various regions (estimated)",
                    _ => "Unknown region"
                };
            }
        }

        /// <summary>
        /// Payload generation and encoding utilities
        /// </summary>
        public static class PayloadGenerator
        {
            /// <summary>
            /// Generates various types of test payloads for security testing
            /// </summary>
            public static Dictionary<string, List<string>> GenerateTestPayloads()
            {
                var payloads = new Dictionary<string, List<string>>();
                
                // XSS payloads (for educational testing only)
                payloads["XSS"] = new List<string>
                {
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "<img src=x onerror=alert('XSS')>",
                    "'><script>alert('XSS')</script>",
                    "\"><script>alert('XSS')</script>"
                };
                
                // SQL injection test patterns (for educational testing only)
                payloads["SQLi"] = new List<string>
                {
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "\" OR \"1\"=\"1",
                    "' UNION SELECT NULL--",
                    "; DROP TABLE users--"
                };
                
                // Directory traversal patterns
                payloads["Directory_Traversal"] = new List<string>
                {
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
                };
                
                // Command injection patterns
                payloads["Command_Injection"] = new List<string>
                {
                    "; ls -la",
                    "| whoami",
                    "&& id",
                    "; cat /etc/passwd",
                    "| net user"
                };
                
                return payloads;
            }

            /// <summary>
            /// Encodes payloads in various formats
            /// </summary>
            public static Dictionary<string, string> EncodePayload(string payload)
            {
                var encoded = new Dictionary<string, string>();
                
                // URL encoding
                encoded["URL"] = Uri.EscapeDataString(payload);
                
                // HTML encoding
                encoded["HTML"] = System.Net.WebUtility.HtmlEncode(payload);
                
                // Base64 encoding
                encoded["Base64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
                
                // Hex encoding
                encoded["Hex"] = Convert.ToHexString(Encoding.UTF8.GetBytes(payload));
                
                // Double URL encoding
                encoded["Double_URL"] = Uri.EscapeDataString(Uri.EscapeDataString(payload));
                
                return encoded;
            }
        }

        /// <summary>
        /// Network evasion techniques
        /// </summary>
        public static class EvasionTechniques
        {
            /// <summary>
            /// Generates decoy traffic to mask real scanning activity
            /// </summary>
            public static async Task GenerateDecoyTraffic(IPAddress target, int duration = 60)
            {
                AnsiConsole.MarkupLine($"[bold cyan]🎭 Generating decoy traffic to {target} for {duration} seconds[/]");
                
                var random = new Random();
                var endTime = DateTime.Now.AddSeconds(duration);
                var tasks = new List<Task>();
                
                while (DateTime.Now < endTime)
                {
                    // Generate random decoy connections
                    var decoyPort = random.Next(1024, 65535);
                    
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            using var client = new TcpClient();
                            var connectTask = client.ConnectAsync(target, decoyPort);
                            var timeoutTask = Task.Delay(random.Next(100, 500));
                            
                            await Task.WhenAny(connectTask, timeoutTask);
                        }
                        catch
                        {
                            // Decoy connection failed, which is expected
                        }
                    }));
                    
                    await Task.Delay(random.Next(50, 200));
                }
                
                await Task.WhenAll(tasks);
                AnsiConsole.MarkupLine("[green]✅ Decoy traffic generation completed[/]");
            }

            /// <summary>
            /// Fragments scanning across multiple source ports
            /// </summary>
            public static async Task<List<int>> FragmentedPortScan(IPAddress target, IEnumerable<int> ports)
            {
                var openPorts = new List<int>();
                var random = new Random();
                
                AnsiConsole.MarkupLine($"[bold cyan]🔀 Performing fragmented scan on {target}[/]");
                
                foreach (var port in ports.OrderBy(x => random.Next()))
                {
                    try
                    {
                        using var client = new TcpClient();
                        
                        // Bind to random source port for fragmentation
                        var localEndpoint = new IPEndPoint(IPAddress.Any, random.Next(1024, 65535));
                        client.Client.Bind(localEndpoint);
                        
                        var connectTask = client.ConnectAsync(target, port);
                        var timeoutTask = Task.Delay(random.Next(1000, 3000));
                        
                        if (await Task.WhenAny(connectTask, timeoutTask) == connectTask && client.Connected)
                        {
                            openPorts.Add(port);
                            AnsiConsole.MarkupLine($"[green]✅ Port {port} open[/]");
                        }
                    }
                    catch
                    {
                        // Port closed or connection failed
                    }
                    
                    // Random delay between scans
                    await Task.Delay(random.Next(100, 1000));
                }
                
                return openPorts;
            }
        }
    }

    /// <summary>
    /// OSINT report structure
    /// </summary>
    public class OsintReport
    {
        public string Domain { get; set; } = string.Empty;
        public List<string> IpAddresses { get; set; } = new();
        public List<string> CloudProviders { get; set; } = new();
        public List<string> GeographicLocations { get; set; } = new();
        public Dictionary<string, List<int>> OpenPorts { get; set; } = new();
        public List<string> SecurityHeaders { get; set; } = new();
        public List<string> MissingSecurityHeaders { get; set; } = new();
        public List<string> Technologies { get; set; } = new();
        public List<string> Errors { get; set; } = new();
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    }
}