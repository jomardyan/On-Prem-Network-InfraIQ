using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;
using Discovery.Core.Constants;
using Discovery.Services.Discovery;
using Discovery.Tools;

namespace Discovery.Services.Utilities
{
    /// <summary>
    /// Provides network utility functions for various network operations
    /// </summary>
    public class NetworkUtilities
    {
        private readonly PingSweeper _pingSweeper;
        private readonly DnsLookupService _dnsLookupService;
        private readonly TracerouteService _tracerouteService;
        private readonly ArpTableScanner _arpTableScanner;
        
        /// <summary>
        /// Initializes a new instance of the NetworkUtilities class
        /// </summary>
        public NetworkUtilities(
            PingSweeper pingSweeper,
            DnsLookupService dnsLookupService,
            TracerouteService tracerouteService,
            ArpTableScanner arpTableScanner)
        {
            _pingSweeper = pingSweeper ?? throw new ArgumentNullException(nameof(pingSweeper));
            _dnsLookupService = dnsLookupService ?? throw new ArgumentNullException(nameof(dnsLookupService));
            _tracerouteService = tracerouteService ?? throw new ArgumentNullException(nameof(tracerouteService));
            _arpTableScanner = arpTableScanner ?? throw new ArgumentNullException(nameof(arpTableScanner));
        }
        
        /// <summary>
        /// Tests the bandwidth by downloading test files and measuring speed
        /// </summary>
        /// <returns>A string with the bandwidth test results</returns>
        public async Task<string> TestBandwidth()
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

        /// <summary>
        /// Gets information about all network interfaces on the system
        /// </summary>
        /// <returns>A formatted string containing network interface details</returns>
        public string GetNetworkInterfaces()
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
                result.Add(string.Empty);
            }
            
            return string.Join("\n", result);
        }

        /// <summary>
        /// Gets the system's routing table
        /// </summary>
        /// <returns>The output of the route command</returns>
        public async Task<string> GetRouteTable()
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

        /// <summary>
        /// Performs a netstat command to list network connections
        /// </summary>
        /// <returns>The output of the netstat command</returns>
        public async Task<string> PerformNetstat()
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

        /// <summary>
        /// Validates if a string is a valid IP address
        /// </summary>
        public bool IsValidIPAddress(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            return IPAddress.TryParse(ipAddress, out _);
        }

        /// <summary>
        /// Validates if a port range is valid
        /// </summary>
        public bool IsValidPortRange(int startPort, int endPort)
        {
            return startPort >= 1 && startPort <= 65535 && 
                   endPort >= 1 && endPort <= 65535 && 
                   startPort <= endPort;
        }

        /// <summary>
        /// Parses a comma-separated string of ports and port ranges
        /// </summary>
        public Dictionary<int, string> ParseCustomPorts(string portsString)
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
        public string GuessOperatingSystem(int ttl)
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
        public (string BaseIp, int StartRange, int EndRange) CalculateNetworkRange(IPAddress networkAddress, IPAddress subnetMask)
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

        /// <summary>
        /// Parses CIDR notation into network address and subnet mask
        /// </summary>
        public bool TryParseCidr(string cidr, out IPAddress? networkAddress, out int subnetMask)
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
