using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Discovery.Core.Utilities;

namespace Discovery.Services.Scanning
{
    /// <summary>
    /// Base class providing common batch scanning functionality for all scanner types
    /// </summary>
    public abstract class BaseBatchScanner
    {
        private static readonly Regex HostnameRegex = new(
            @"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            RegexOptions.Compiled);
        /// <summary>
        /// Parses CSV content into individual target strings
        /// </summary>
        /// <param name="csvContent">CSV content with targets (IPs, CIDRs, ranges)</param>
        /// <returns>Collection of individual target strings</returns>
        protected virtual IEnumerable<string> ParseCsvTargets(string csvContent)
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

        /// <summary>
        /// Expands target strings (IPs, CIDRs, ranges) into individual IP addresses
        /// </summary>
        /// <param name="targets">Collection of target strings</param>
        /// <returns>Collection of individual IP addresses</returns>
        protected virtual IEnumerable<string> ExpandTargetsToIps(IEnumerable<string> targets)
        {
            foreach (var target in targets)
            {
                foreach (var ip in ExpandSingleTargetToIps(target))
                {
                    yield return ip;
                }
            }
        }

        /// <summary>
        /// Expands a single target string into individual IP addresses
        /// </summary>
        /// <param name="target">Target string (IP, CIDR, or range)</param>
        /// <returns>Collection of individual IP addresses</returns>
        protected virtual IEnumerable<string> ExpandSingleTargetToIps(string target)
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

        /// <summary>
        /// Expands CIDR notation to individual IP addresses
        /// </summary>
        /// <param name="cidr">CIDR notation (e.g., 192.168.1.0/24)</param>
        /// <returns>Collection of IP addresses in the network</returns>
        protected virtual IEnumerable<string> ExpandCidrToIps(string cidr)
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

        /// <summary>
        /// Expands IP range notation to individual IP addresses
        /// </summary>
        /// <param name="range">IP range (e.g., 192.168.1.1-192.168.1.10 or 192.168.1.1-10)</param>
        /// <returns>Collection of IP addresses in the range</returns>
        protected virtual IEnumerable<string> ExpandRangeToIps(string range)
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

        /// <summary>
        /// Gets all IP addresses between start and end addresses (inclusive)
        /// </summary>
        protected virtual IEnumerable<string> GetIpRange(IPAddress startIp, IPAddress endIp)
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

        /// <summary>
        /// Parses CIDR notation into network address and subnet mask
        /// </summary>
        protected virtual bool TryParseCidr(string cidr, out IPAddress? networkAddress, out int subnetMask)
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
        /// Checks if a string is a valid hostname
        /// </summary>
        protected virtual bool IsValidHostname(string hostname)
        {
            if (string.IsNullOrWhiteSpace(hostname) || hostname.Length > 253)
                return false;

            return HostnameRegex.IsMatch(hostname);
        }

        /// <summary>
        /// Resolves hostname to IP addresses
        /// </summary>
        protected virtual IEnumerable<string> ResolveHostnameToIps(string hostname)
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

        /// <summary>
        /// Processes batch scanning by expanding targets and scanning each IP
        /// </summary>
        protected virtual async Task<List<ScanResult>> ProcessBatchScanAsync(
            IEnumerable<string> targets, 
            Dictionary<int, string> portsToScan, 
            CancellationToken cancellationToken,
            Func<string, Dictionary<int, string>, CancellationToken, Task<List<ScanResult>>> scanSingleIpFunc)
        {
            var allResults = new List<ScanResult>();
            var expandedIps = ExpandTargetsToIps(targets).Distinct().ToList();
            
            // Skip interactive prompts in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment && expandedIps.Count > 50)
            {
                Console.WriteLine($"About to scan {expandedIps.Count} IP addresses. This may take a while.");
                Console.Write("Continue? (y/N): ");
                var response = Console.ReadLine();
                if (!string.Equals(response?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Scan cancelled by user.");
                    return allResults;
                }
            }

            // Use a semaphore to limit concurrent scans
            using var semaphore = new SemaphoreSlim(Math.Min(50, expandedIps.Count), Math.Min(50, expandedIps.Count));
            
            var tasks = expandedIps.Select(async ip =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    return await scanSingleIpFunc(ip, portsToScan, cancellationToken);
                }
                catch (Exception ex)
                {
                    // Log error but continue with other IPs
                    Console.WriteLine($"Error scanning {ip}: {ex.Message}");
                    return new List<ScanResult>();
                }
                finally
                {
                    semaphore.Release();
                }
            });

            var results = await Task.WhenAll(tasks);
            
            foreach (var result in results)
            {
                allResults.AddRange(result);
            }

            return allResults;
        }
    }
}