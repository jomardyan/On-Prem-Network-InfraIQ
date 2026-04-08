using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;

namespace Discovery.Core.Interfaces
{
    /// <summary>
    /// Interface defining the contract for network scanning operations with comprehensive batch scanning capabilities
    /// </summary>
    public interface IScanner
    {
        /// <summary>
        /// Scans a single IP address for open ports
        /// </summary>
        Task<List<ScanResult>> ScanSingleIpAsync(string ipAddress, Dictionary<int, string> portsToScan, CancellationToken cancellationToken);
        
        /// <summary>
        /// Scans a range of IP addresses for open ports
        /// </summary>
        Task<List<ScanResult>> ScanNetworkRangeAsync(string baseIp, int startRange, int endRange, Dictionary<int, string> portsToScan, CancellationToken cancellationToken);
        
        /// <summary>
        /// Scans a CIDR network for open ports
        /// </summary>
        Task<List<ScanResult>> ScanCidrNetworkAsync(IPAddress networkAddress, int subnetMask, Dictionary<int, string> portsToScan, CancellationToken cancellationToken);
        
        /// <summary>
        /// Scans a CIDR network using string notation for open ports
        /// </summary>
        Task<List<ScanResult>> ScanCidrNetworkAsync(string cidrNotation, Dictionary<int, string> portsToScan, CancellationToken cancellationToken);
        
        /// <summary>
        /// Scans a range of public IP addresses for open ports
        /// </summary>
        Task<List<ScanResult>> ScanPublicIpRangeAsync(IPAddress startIp, IPAddress endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken);
        
        /// <summary>
        /// Scans a range of IP addresses using string notation for open ports
        /// </summary>
        Task<List<ScanResult>> ScanIpRangeAsync(string startIp, string endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken);
        
        /// <summary>
        /// Scans multiple targets from a CSV list containing IP addresses, CIDR networks, and IP ranges
        /// </summary>
        Task<List<ScanResult>> ScanCsvTargetsAsync(string csvContent, Dictionary<int, string> portsToScan, CancellationToken cancellationToken);
        
        /// <summary>
        /// Scans multiple targets from a list of target strings (IPs, CIDRs, ranges)
        /// </summary>
        Task<List<ScanResult>> ScanBatchTargetsAsync(IEnumerable<string> targets, Dictionary<int, string> portsToScan, CancellationToken cancellationToken);
    }
}
