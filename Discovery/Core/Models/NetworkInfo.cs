using System.Net;

namespace Discovery.Core.Models
{
    /// <summary>
    /// Contains information about a network including IP address range, subnet mask, and more
    /// </summary>
    public class NetworkInfo
    {
        /// <summary>
        /// The network address (e.g. 192.168.1.0)
        /// </summary>
        public IPAddress NetworkAddress { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The subnet mask in CIDR notation (e.g. 24 for /24)
        /// </summary>
        public int PrefixLength { get; set; }
        
        /// <summary>
        /// The broadcast address for this network
        /// </summary>
        public IPAddress BroadcastAddress { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The first usable host IP in this network
        /// </summary>
        public IPAddress FirstUsableIp { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The last usable host IP in this network
        /// </summary>
        public IPAddress LastUsableIp { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The total number of usable host IPs in this network.
        /// </summary>
        public long UsableHosts { get; set; }
        
        /// <summary>
        /// The subnet mask as an IP address (e.g. 255.255.255.0)
        /// </summary>
        public IPAddress SubnetMask { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The wildcard mask as an IP address (inverse of subnet mask)
        /// </summary>
        public IPAddress WildcardMask { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The original IP address that was used for calculation
        /// </summary>
        public IPAddress IpAddress { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The total number of hosts in this network (including network and broadcast)
        /// </summary>
        public long TotalHosts { get; set; }
        
        /// <summary>
        /// The network class (A, B, C, etc.)
        /// </summary>
        public string NetworkClass { get; set; } = string.Empty;
        
        /// <summary>
        /// Whether this is a private network address
        /// </summary>
        public bool IsPrivate { get; set; }
        
        /// <summary>
        /// Gets the CIDR notation for this network (e.g. 192.168.1.0/24)
        /// </summary>
        public string CidrNotation => $"{NetworkAddress}/{PrefixLength}";
    }
}
