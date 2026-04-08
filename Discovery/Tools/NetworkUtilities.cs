using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using Spectre.Console;
using Discovery.Core;
using Discovery.Core.Constants;

namespace Discovery.Tools
{
    public static class NetworkUtilities
    {
        public static async Task<List<string>> PingSweep(string network)
        {
            var aliveHosts = new List<string>();
            
            if (!TryParseCidr(network, out var networkAddress, out var subnetMask) || networkAddress == null)
            {
                AnsiConsole.MarkupLine("[red]❌ Invalid CIDR notation.[/]");
                return aliveHosts;
            }

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
                    var networkBytes = networkAddress.GetAddressBytes();
                    uint network_uint = (uint)networkBytes[0] << 24 | (uint)networkBytes[1] << 16 | (uint)networkBytes[2] << 8 | networkBytes[3];
                    
                    uint mask = 0xFFFFFFFF << (32 - subnetMask);
                    network_uint = network_uint & mask;
                    
                    uint hostBits = (uint)(32 - subnetMask);
                    uint totalHosts = (uint)(Math.Pow(2, hostBits) - 2);
                    
                    var pingTask = ctx.AddTask("[green]📡 Pinging hosts[/]");
                    pingTask.MaxValue = totalHosts;
                    
                    var semaphore = new SemaphoreSlim(50);
                    var tasks = new List<Task>();
                    
                    for (uint i = 1; i <= totalHosts; i++)
                    {
                        uint currentIp = network_uint + i;
                        var ipBytes = new byte[4];
                        ipBytes[0] = (byte)(currentIp >> 24);
                        ipBytes[1] = (byte)(currentIp >> 16);
                        ipBytes[2] = (byte)(currentIp >> 8);
                        ipBytes[3] = (byte)currentIp;
                        var ipToTest = new IPAddress(ipBytes).ToString();
                        
                        await semaphore.WaitAsync();
                        tasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                if (IPAddress.TryParse(ipToTest, out var ip))
                                {
                                    var result = await NetworkScanner.PingHostAsync(ip, 1000);
                                    if (result.Success)
                                    {
                                        lock (aliveHosts)
                                        {
                                            aliveHosts.Add($"{ipToTest} ({result.ResponseTime}ms)");
                                        }
                                    }
                                }
                            }
                            finally
                            {
                                pingTask.Increment(1);
                                semaphore.Release();
                            }
                        }));
                    }
                    await Task.WhenAll(tasks);
                });

            return aliveHosts.OrderBy(h => h).ToList();
        }

        public static async Task<string> GetDnsInformation(string hostname)
        {
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(hostname);
                var result = $"🌐 Hostname: {hostEntry.HostName}\n";
                
                foreach (var alias in hostEntry.Aliases)
                {
                    result += $"🔗 Alias: {alias}\n";
                }
                
                foreach (var address in hostEntry.AddressList)
                {
                    result += $"📍 {address.AddressFamily} Address: {address}\n";
                }
                
                return result;
            }
            catch (Exception ex)
            {
                return $"❌ DNS lookup failed: {ex.Message}";
            }
        }

        public static async Task<string> GetReverseDns(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out var ip))
            {
                return "❌ Invalid IP address format.";
            }
            
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(ip);
                var result = $"🔄 Reverse DNS: {ip} → {hostEntry.HostName}\n";
                
                if (hostEntry.Aliases.Any())
                {
                    result += "🔗 Aliases:\n";
                    foreach (var alias in hostEntry.Aliases)
                    {
                        result += $"  • {alias}\n";
                    }
                }
                return result;
            }
            catch (Exception ex)
            {
                return $"❌ Reverse DNS lookup failed: {ex.Message}";
            }
        }

        public static async Task<string> GetWhoisInformation(string domain)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("whois.iana.org", 43);
                
                using var stream = client.GetStream();
                using var writer = new StreamWriter(stream);
                using var reader = new StreamReader(stream);
                
                await writer.WriteLineAsync(domain);
                await writer.FlushAsync();
                
                var response = await reader.ReadToEndAsync();
                
                return !string.IsNullOrEmpty(response) ? response : "❌ No WHOIS information found.";
            }
            catch (Exception ex)
            {
                return $"❌ WHOIS lookup failed: {ex.Message}";
            }
        }

        public static async Task<string> PerformTraceroute(string target)
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "traceroute",
                        Arguments = target,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                return !string.IsNullOrEmpty(output) ? output : "❌ Traceroute failed or no output received.";
            }
            catch (Exception ex)
            {
                return $"❌ Traceroute failed: {ex.Message}\n💡 Note: This feature requires 'traceroute' to be installed on your system.";
            }
        }

        public static async Task<string> TestBandwidth()
        {
            var testUrls = new[]
            {
                "http://speedtest.ftp.otenet.gr/files/test100k.db",
                "http://speedtest.ftp.otenet.gr/files/test1Mb.db"
            };
            
            var results = new List<string>();
            
            using var httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromSeconds(30);
            
            foreach (var url in testUrls)
            {
                try
                {
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    var response = await httpClient.GetAsync(url);
                    var data = await response.Content.ReadAsByteArrayAsync();
                    stopwatch.Stop();
                    
                    var sizeMB = data.Length / (1024.0 * 1024.0);
                    var speedMbps = (sizeMB * 8) / (stopwatch.ElapsedMilliseconds / 1000.0);
                    
                    results.Add($"📊 Downloaded {sizeMB:F2} MB in {stopwatch.ElapsedMilliseconds}ms");
                    results.Add($"🚀 Speed: {speedMbps:F2} Mbps");
                }
                catch (Exception ex)
                {
                    results.Add($"❌ Bandwidth test failed: {ex.Message}");
                }
                
                await Task.Delay(1000); // Wait between tests
            }
            
            return string.Join("\n", results);
        }

        public static string GetNetworkInterfaces()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            var result = new List<string>();
            
            foreach (var iface in interfaces)
            {
                var ipAddresses = iface.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString())
                    .ToList();
                
                var speed = iface.Speed > 0 ? $"{iface.Speed / 1_000_000} Mbps" : "Unknown";
                var ips = ipAddresses.Any() ? string.Join(", ", ipAddresses) : "None";
                
                result.Add($"🖥️ {iface.Name}");
                result.Add($"   Type: {iface.NetworkInterfaceType}");
                result.Add($"   Status: {iface.OperationalStatus}");
                result.Add($"   Speed: {speed}");
                result.Add($"   IPs: {ips}");
                result.Add("");
            }
            
            return string.Join("\n", result);
        }

        public static async Task<string> GetRouteTable()
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "route",
                        Arguments = "-n",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                return !string.IsNullOrEmpty(output) ? output : "❌ Could not retrieve route table.";
            }
            catch (Exception ex)
            {
                return $"❌ Error retrieving route table: {ex.Message}";
            }
        }

        public static async Task<string> GetArpTable()
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = "-a",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                return !string.IsNullOrEmpty(output) ? output : "❌ Could not retrieve ARP table.";
            }
            catch (Exception ex)
            {
                return $"❌ Error retrieving ARP table: {ex.Message}";
            }
        }

        public static async Task<string> PerformNetstat()
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "netstat",
                        Arguments = "-tulpn",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                return !string.IsNullOrEmpty(output) ? output : "❌ Could not retrieve network connections.";
            }
            catch (Exception ex)
            {
                return $"❌ Error retrieving network connections: {ex.Message}";
            }
        }

        public static async Task<string> PerformNslookup(string domain, string recordType = "A")
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "nslookup",
                        Arguments = $"-type={recordType} {domain}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                return !string.IsNullOrEmpty(output) ? output : "❌ DNS lookup failed.";
            }
            catch (Exception ex)
            {
                return $"❌ DNS lookup failed: {ex.Message}";
            }
        }

        /// <summary>
        /// Validates if a string is a valid IP address
        /// </summary>
        public static bool IsValidIPAddress(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            return IPAddress.TryParse(ipAddress, out _);
        }

        /// <summary>
        /// Validates if a port range is valid
        /// </summary>
        public static bool IsValidPortRange(int startPort, int endPort)
        {
            return startPort >= 1 && startPort <= 65535 && 
                   endPort >= 1 && endPort <= 65535 && 
                   startPort <= endPort;
        }

        /// <summary>
        /// Parses a comma-separated string of ports and port ranges
        /// </summary>
        public static Dictionary<int, string> ParseCustomPorts(string portsString)
        {
            var ports = new Dictionary<int, string>();
            
            if (string.IsNullOrWhiteSpace(portsString))
                return ports;

            var parts = portsString.Split(',');

            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                
                try
                {
                    // Handle port ranges (e.g., 8080-8090)
                    if (trimmed.Contains('-'))
                    {
                        var rangeParts = trimmed.Split('-');
                        if (rangeParts.Length == 2 && 
                            int.TryParse(rangeParts[0].Trim(), out int start) && 
                            int.TryParse(rangeParts[1].Trim(), out int end) &&
                            start <= end && start > 0 && end <= 65535)
                        {
                            for (int port = start; port <= end; port++)
                            {
                                string service = NetworkConstants.PopularPorts.ContainsKey(port) ? 
                                    NetworkConstants.PopularPorts[port] : "Unknown";
                                ports[port] = service;
                            }
                        }
                    }
                    // Handle single ports
                    else if (int.TryParse(trimmed, out int port) && port > 0 && port <= 65535)
                    {
                        string service = NetworkConstants.PopularPorts.ContainsKey(port) ? 
                            NetworkConstants.PopularPorts[port] : "Unknown";
                        ports[port] = service;
                    }
                }
                catch
                {
                    // Ignore invalid entries silently
                }
            }

            return ports;
        }

        /// <summary>
        /// Guesses the operating system based on TTL value
        /// </summary>
        public static string GuessOperatingSystem(int ttl)
        {
            return ttl switch
            {
                <= 64 => "Linux/Unix",
                <= 128 => "Windows",
                <= 255 => "Cisco/Network Device",
                _ => "Unknown"
            };
        }

        /// <summary>
        /// Calculates network range from network address and subnet mask
        /// </summary>
        public static (string BaseIp, int StartRange, int EndRange) CalculateNetworkRange(IPAddress networkAddress, IPAddress subnetMask)
        {
            var networkBytes = networkAddress.GetAddressBytes();
            var maskBytes = subnetMask.GetAddressBytes();
            
            var networkCalc = new byte[4];
            var broadcastCalc = new byte[4];
            
            for (int i = 0; i < 4; i++)
            {
                networkCalc[i] = (byte)(networkBytes[i] & maskBytes[i]);
                broadcastCalc[i] = (byte)(networkBytes[i] | ~maskBytes[i]);
            }
            
            string baseIp = $"{networkCalc[0]}.{networkCalc[1]}.{networkCalc[2]}.";
            int startRange = networkCalc[3] == 0 ? 1 : networkCalc[3]; // Skip network address if it's .0
            int endRange = broadcastCalc[3] == 255 ? 254 : broadcastCalc[3]; // Skip broadcast if it's .255
            
            return (baseIp, startRange, endRange);
        }

        public static bool TryParseCidr(string cidr, out IPAddress? networkAddress, out int subnetMask)
        {
            networkAddress = null;
            subnetMask = 0;
            if (string.IsNullOrWhiteSpace(cidr))
                return false;

            var parts = cidr.Split('/');
            if (parts.Length != 2)
                return false;

            if (!IPAddress.TryParse(parts[0], out var ip))
                return false;

            if (!int.TryParse(parts[1], out int mask) || mask < 0 || mask > 32)
                return false;

            networkAddress = ip;
            subnetMask = mask;
            return true;
        }
    }
}
