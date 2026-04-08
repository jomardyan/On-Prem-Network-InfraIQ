using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Discovery.Display;
using Spectre.Console;

namespace Discovery.Services.Scanning
{
    /// <summary>
    /// Implements CIDR-specific network scanning functionality
    /// </summary>
    public class CidrScanner
    {
        private readonly PortScanner _portScanner;

        public CidrScanner(PortScanner portScanner)
        {
            _portScanner = portScanner ?? throw new ArgumentNullException(nameof(portScanner));
        }

        /// <summary>
        /// Parses CIDR notation into network address and subnet mask
        /// </summary>
        /// <param name="cidr">The CIDR notation (e.g. 192.168.1.0/24)</param>
        /// <param name="networkAddress">Output network address</param>
        /// <param name="subnetMask">Output subnet mask</param>
        /// <returns>True if parsing succeeded, otherwise false</returns>
        public bool TryParseCidr(string cidr, out IPAddress? networkAddress, out int subnetMask)
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

        /// <summary>
        /// Scans a network using CIDR notation
        /// </summary>
        public async Task<List<ScanResult>> ScanCidrNotation(string cidrNotation, Dictionary<int, string> portsToScan, CancellationTokenSource cts)
        {
            if (!TryParseCidr(cidrNotation, out var networkAddress, out var subnetMask) || networkAddress == null)
            {
                AnsiConsole.MarkupLine("[bold red]Invalid CIDR notation.[/]");
                return new List<ScanResult>();
            }

            return await _portScanner.ScanCidrNetworkAsync(networkAddress, subnetMask, portsToScan, cts.Token);
        }

        /// <summary>
        /// Calculates the total number of hosts in a CIDR network
        /// </summary>
        public uint CalculateTotalHosts(int subnetMask)
        {
            uint hostBits = (uint)(32 - subnetMask);
            return (uint)(Math.Pow(2, hostBits) - 2); // Exclude network and broadcast addresses
        }
        
        /// <summary>
        /// Converts IP bytes to uint representation for CIDR calculations
        /// </summary>
        public uint ConvertIpToUint(byte[] ipBytes)
        {
            return (uint)ipBytes[0] << 24 | (uint)ipBytes[1] << 16 | (uint)ipBytes[2] << 8 | ipBytes[3];
        }

        /// <summary>
        /// Converts uint to IP address bytes
        /// </summary>
        public byte[] ConvertUintToIpBytes(uint ipUint)
        {
            var bytes = new byte[4];
            bytes[0] = (byte)(ipUint >> 24);
            bytes[1] = (byte)(ipUint >> 16);
            bytes[2] = (byte)(ipUint >> 8);
            bytes[3] = (byte)ipUint;
            return bytes;
        }

        /// <summary>
        /// Gets the network mask as a uint
        /// </summary>
        public uint GetNetworkMask(int cidrPrefix)
        {
            return 0xFFFFFFFF << (32 - cidrPrefix);
        }

        /// <summary>
        /// Asynchronously scans a CIDR network range for active hosts
        /// </summary>
        /// <param name="cidr">The CIDR notation (e.g. 192.168.1.0/24)</param>
        /// <param name="timeout">Timeout in milliseconds for each ping request</param>
        /// <returns>A list of active host IP addresses</returns>
        public async Task<List<string>> ScanCidrAsync(string cidr, int timeout = 1000)
        {
            if (!TryParseCidr(cidr, out var networkAddress, out var subnetMask) || networkAddress == null)
            {
                AnsiConsole.MarkupLine("[bold red]Invalid CIDR notation.[/]");
                return new List<string>();
            }

            var result = new List<string>();
            var ipBytes = networkAddress.GetAddressBytes();
            var networkIp = ConvertIpToUint(ipBytes);
            var mask = GetNetworkMask(subnetMask);
            var networkStart = networkIp & mask;
            var hostCount = (int)CalculateTotalHosts(subnetMask);

            var tasks = new List<Task<bool>>();
            var hosts = new List<string>();

            // Generate all host addresses in the subnet
            for (int i = 1; i <= hostCount; i++)
            {
                var hostIp = networkStart + (uint)i;
                var hostBytes = ConvertUintToIpBytes(hostIp);
                var hostAddress = new IPAddress(hostBytes).ToString();
                hosts.Add(hostAddress);
            }

            // Use a SemaphoreSlim to limit concurrency
            using var semaphore = new SemaphoreSlim(50); // Process 50 hosts at a time
            var pingTasks = hosts.Select(async host => 
            {
                await semaphore.WaitAsync();
                try
                {
                    var isAlive = await PingHostAsync(host, timeout);
                    if (isAlive)
                    {
                        lock (result)
                        {
                            result.Add(host);
                        }
                    }
                    return isAlive;
                }
                finally
                {
                    semaphore.Release();
                }
            }).ToList();

            await Task.WhenAll(pingTasks);
            return result;
        }

        /// <summary>
        /// Pings a host to determine if it's alive
        /// </summary>
        /// <param name="host">The host IP address</param>
        /// <param name="timeout">Timeout in milliseconds</param>
        /// <returns>True if the host responded, false otherwise</returns>
        private async Task<bool> PingHostAsync(string host, int timeout)
        {
            // Try both common ports in parallel rather than sequentially to halve failure latency
            var task80 = TestTcpPortAsync(host, 80, timeout);
            var task443 = TestTcpPortAsync(host, 443, timeout);

            var first = await Task.WhenAny(task80, task443);
            if (await first)
                return true;

            // First task failed; await the second. If the first succeeded we return early and the
            // other task continues to its natural completion (TestTcpPortAsync handles all exceptions
            // internally so there is no risk of an unobserved exception).
            var second = first == task80 ? task443 : task80;
            return await second;
        }

        private async Task<bool> TestTcpPortAsync(string host, int port, int timeout)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(timeout);
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                return completedTask == connectTask && client.Connected;
            }
            catch
            {
                return false;
            }
        }
    }
}
