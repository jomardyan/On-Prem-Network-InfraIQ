using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Linq;
using Discovery.Core.Models;

namespace Discovery.Tools.RouterScanning
{
    /// <summary>
    /// Router fingerprinting engine to identify router brands and models
    /// </summary>
    public static class RouterFingerprinter
    {
        public enum RouterBrand
        {
            Unknown,
            Cisco,
            Mikrotik,
            Ubiquiti,
            Netgear,
            TPLink,
            DLink,
            Linksys,
            Asus,
            DDWrt,
            OpenWrt,
            Juniper,
            Fortinet,
            SonicWall,
            Palo_Alto,
            Huawei
        }

        public class RouterIdentification
        {
            public RouterBrand Brand { get; set; }
            public string Model { get; set; } = "";
            public string Firmware { get; set; } = "";
            public string ManagementInterface { get; set; } = "";
            public List<int> ManagementPorts { get; set; } = new();
            public Dictionary<string, string> ServiceBanners { get; set; } = new();
            public float ConfidenceScore { get; set; }
            public List<string> DetectionMethods { get; set; } = new();
        }

        private static readonly Dictionary<RouterBrand, RouterSignature> RouterSignatures = new()
        {
            [RouterBrand.Cisco] = new RouterSignature
            {
                CommonPorts = new[] { 22, 23, 80, 443, 161, 8443 },
                HttpTitlePatterns = new[] { "Cisco", "IOS", "Catalyst", "ASA", "ISR" },
                BannerPatterns = new[] { "Cisco IOS", "Cisco Internetwork Operating System", "Cisco ASA", "User Access Verification" },
                SshBannerPatterns = new[] { "SSH-2.0-Cisco", "Cisco-1." },
                HttpServerHeaders = new[] { "cisco-IOS", "cisco-asa" },
                SnmpOids = new[] { "1.3.6.1.4.1.9" } // Cisco enterprise OID
            },
            [RouterBrand.Mikrotik] = new RouterSignature
            {
                CommonPorts = new[] { 22, 23, 80, 443, 8291, 8728, 8729, 2000 },
                HttpTitlePatterns = new[] { "RouterOS", "MikroTik", "Winbox" },
                BannerPatterns = new[] { "MikroTik", "RouterOS" },
                SshBannerPatterns = new[] { "SSH-2.0-ROSSSH" },
                HttpServerHeaders = new[] { "RouterOS" },
                SnmpOids = new[] { "1.3.6.1.4.1.14988" } // MikroTik enterprise OID
            },
            [RouterBrand.Ubiquiti] = new RouterSignature
            {
                CommonPorts = new[] { 22, 80, 443, 8080, 8443, 8880, 8843 },
                HttpTitlePatterns = new[] { "UniFi", "EdgeRouter", "AirRouter", "Ubiquiti" },
                BannerPatterns = new[] { "Ubiquiti", "EdgeOS", "UniFi" },
                SshBannerPatterns = new[] { "SSH-2.0-OpenSSH", "EdgeOS" },
                HttpServerHeaders = new[] { "lighttpd" },
                SnmpOids = new[] { "1.3.6.1.4.1.41112" } // Ubiquiti enterprise OID
            }
        };

        private class RouterSignature
        {
            public int[] CommonPorts { get; set; } = Array.Empty<int>();
            public string[] HttpTitlePatterns { get; set; } = Array.Empty<string>();
            public string[] BannerPatterns { get; set; } = Array.Empty<string>();
            public string[] SshBannerPatterns { get; set; } = Array.Empty<string>();
            public string[] HttpServerHeaders { get; set; } = Array.Empty<string>();
            public string[] SnmpOids { get; set; } = Array.Empty<string>();
        }

        /// <summary>
        /// Identify router brand and model by fingerprinting various services
        /// </summary>
        public static async Task<RouterIdentification> IdentifyRouterAsync(IPAddress ipAddress)
        {
            var identification = new RouterIdentification();
            var tasks = new List<Task>();

            // HTTP/HTTPS fingerprinting
            tasks.Add(Task.Run(async () =>
            {
                var httpResult = await FingerprintHttpAsync(ipAddress);
                if (httpResult.Brand != RouterBrand.Unknown)
                {
                    identification = MergeIdentification(identification, httpResult);
                }
            }));

            // SSH fingerprinting
            tasks.Add(Task.Run(async () =>
            {
                var sshResult = await FingerprintSshAsync(ipAddress);
                if (sshResult.Brand != RouterBrand.Unknown)
                {
                    identification = MergeIdentification(identification, sshResult);
                }
            }));

            // Port scanning for router-specific services
            tasks.Add(Task.Run(async () =>
            {
                var portResult = await FingerprintPortsAsync(ipAddress);
                if (portResult.Brand != RouterBrand.Unknown)
                {
                    identification = MergeIdentification(identification, portResult);
                }
            }));

            // SNMP fingerprinting
            tasks.Add(Task.Run(async () =>
            {
                var snmpResult = await FingerprintSnmpAsync(ipAddress);
                if (snmpResult.Brand != RouterBrand.Unknown)
                {
                    identification = MergeIdentification(identification, snmpResult);
                }
            }));

            await Task.WhenAll(tasks);

            // Calculate final confidence score
            identification.ConfidenceScore = CalculateConfidence(identification);

            return identification;
        }

        private static async Task<RouterIdentification> FingerprintHttpAsync(IPAddress ipAddress)
        {
            var identification = new RouterIdentification();
            
            foreach (var port in new[] { 80, 443, 8080, 8443 })
            {
                try
                {
                    using var client = new System.Net.Http.HttpClient();
                    client.Timeout = TimeSpan.FromSeconds(5);
                    
                    var protocol = port == 443 || port == 8443 ? "https" : "http";
                    var response = await client.GetAsync($"{protocol}://{ipAddress}:{port}");
                    
                    var content = await response.Content.ReadAsStringAsync();
                    var headers = response.Headers.ToString();

                    // Check for router-specific patterns
                    foreach (var kvp in RouterSignatures)
                    {
                        var brand = kvp.Key;
                        var signature = kvp.Value;

                        foreach (var pattern in signature.HttpTitlePatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                identification.Brand = brand;
                                identification.DetectionMethods.Add($"HTTP title pattern: {pattern}");
                                identification.ManagementInterface = $"{protocol}://{ipAddress}:{port}";
                                identification.ManagementPorts.Add(port);
                                break;
                            }
                        }

                        foreach (var serverHeader in signature.HttpServerHeaders)
                        {
                            if (headers.Contains(serverHeader, StringComparison.OrdinalIgnoreCase))
                            {
                                identification.Brand = brand;
                                identification.DetectionMethods.Add($"HTTP server header: {serverHeader}");
                                identification.ManagementInterface = $"{protocol}://{ipAddress}:{port}";
                                identification.ManagementPorts.Add(port);
                                break;
                            }
                        }
                    }

                    // Extract specific router information
                    ExtractRouterDetails(content, identification);
                }
                catch
                {
                    // Continue with next port
                }
            }

            return identification;
        }

        private static async Task<RouterIdentification> FingerprintSshAsync(IPAddress ipAddress)
        {
            var identification = new RouterIdentification();

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(ipAddress, 22);
                
                using var stream = client.GetStream();
                var buffer = new byte[1024];
                var received = await stream.ReadAsync(buffer, 0, buffer.Length);
                var banner = Encoding.UTF8.GetString(buffer, 0, received);

                identification.ServiceBanners["SSH"] = banner.Trim();

                foreach (var kvp in RouterSignatures)
                {
                    var brand = kvp.Key;
                    var signature = kvp.Value;

                    foreach (var pattern in signature.SshBannerPatterns)
                    {
                        if (banner.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            identification.Brand = brand;
                            identification.DetectionMethods.Add($"SSH banner pattern: {pattern}");
                            identification.ManagementPorts.Add(22);
                            break;
                        }
                    }
                }
            }
            catch
            {
                // SSH not available or connection failed
            }

            return identification;
        }

        private static async Task<RouterIdentification> FingerprintPortsAsync(IPAddress ipAddress)
        {
            var identification = new RouterIdentification();
            var openPorts = new List<int>();

            // Check for router-specific ports
            var routerPorts = new[]
            {
                8291, // MikroTik Winbox
                8728, // MikroTik API
                8729, // MikroTik API SSL
                2000, // MikroTik Bandwidth test
                8080, // Various routers
                8443, // Various routers
                161,  // SNMP
                9100  // HP JetDirect (some enterprise routers)
            };

            var tasks = routerPorts.Select(async port =>
            {
                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(2000)) == connectTask)
                    {
                        await connectTask;
                        openPorts.Add(port);
                    }
                }
                catch
                {
                    // Port closed or filtered
                }
            });

            await Task.WhenAll(tasks);

            // Analyze port patterns
            if (openPorts.Contains(8291) || openPorts.Contains(8728))
            {
                identification.Brand = RouterBrand.Mikrotik;
                identification.DetectionMethods.Add("MikroTik-specific ports detected");
                identification.ManagementPorts.AddRange(openPorts);
            }

            return identification;
        }

        private static async Task<RouterIdentification> FingerprintSnmpAsync(IPAddress ipAddress)
        {
            var identification = new RouterIdentification();

            try
            {
                // Basic SNMP fingerprinting (simplified implementation)
                // In a real implementation, you would use an SNMP library
                // For now, we'll just check if SNMP port is open using TCP first
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, 161);
                if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask)
                {
                    await connectTask;
                    identification.DetectionMethods.Add("SNMP available");
                    identification.ManagementPorts.Add(161);
                }
            }
            catch
            {
                // SNMP not available
            }

            return identification;
        }

        private static void ExtractRouterDetails(string content, RouterIdentification identification)
        {
            // Extract firmware version, model information from HTML content
            var patterns = new Dictionary<string, string>
            {
                [@"IOS.*Version\s+([\d\.]+)"] = "firmware",
                [@"RouterOS\s+([\d\.]+)"] = "firmware",
                [@"EdgeOS\s+v([\d\.]+)"] = "firmware",
                [@"Model:\s*([A-Za-z0-9\-]+)"] = "model"
            };

            foreach (var kvp in patterns)
            {
                var match = Regex.Match(content, kvp.Key, RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    if (kvp.Value == "firmware")
                    {
                        identification.Firmware = match.Groups[1].Value;
                    }
                    else if (kvp.Value == "model")
                    {
                        identification.Model = match.Groups[1].Value;
                    }
                }
            }
        }

        private static RouterIdentification MergeIdentification(RouterIdentification existing, RouterIdentification newData)
        {
            if (newData.Brand != RouterBrand.Unknown && existing.Brand == RouterBrand.Unknown)
            {
                existing.Brand = newData.Brand;
            }

            if (!string.IsNullOrEmpty(newData.Model) && string.IsNullOrEmpty(existing.Model))
            {
                existing.Model = newData.Model;
            }

            if (!string.IsNullOrEmpty(newData.Firmware) && string.IsNullOrEmpty(existing.Firmware))
            {
                existing.Firmware = newData.Firmware;
            }

            if (!string.IsNullOrEmpty(newData.ManagementInterface) && string.IsNullOrEmpty(existing.ManagementInterface))
            {
                existing.ManagementInterface = newData.ManagementInterface;
            }

            existing.ManagementPorts.AddRange(newData.ManagementPorts.Where(p => !existing.ManagementPorts.Contains(p)));
            existing.DetectionMethods.AddRange(newData.DetectionMethods);

            foreach (var banner in newData.ServiceBanners)
            {
                existing.ServiceBanners[banner.Key] = banner.Value;
            }

            return existing;
        }

        private static float CalculateConfidence(RouterIdentification identification)
        {
            float confidence = 0;

            if (identification.Brand != RouterBrand.Unknown) confidence += 30;
            if (!string.IsNullOrEmpty(identification.Model)) confidence += 20;
            if (!string.IsNullOrEmpty(identification.Firmware)) confidence += 20;
            if (identification.ManagementPorts.Count > 0) confidence += 15;
            if (identification.ServiceBanners.Count > 0) confidence += 10;
            confidence += identification.DetectionMethods.Count * 5;

            return Math.Min(confidence, 100);
        }
    }
}