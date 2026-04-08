using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Discovery.Services.Utilities
{
    /// <summary>
    /// Service for collecting and analyzing network interface information
    /// </summary>
    public class NetworkInterfaceInfo
    {
        /// <summary>
        /// Gets detailed information about all available network interfaces
        /// </summary>
        /// <returns>A list of detailed interface information</returns>
        public IEnumerable<InterfaceDetails> GetAllNetworkInterfaces()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            var result = new List<InterfaceDetails>();
            
            foreach (var nic in interfaces)
            {
                var interfaceDetails = new InterfaceDetails
                {
                    Name = nic.Name,
                    Description = nic.Description,
                    Type = nic.NetworkInterfaceType,
                    Status = nic.OperationalStatus,
                    Speed = nic.Speed,
                    MacAddress = FormatMacAddress(nic.GetPhysicalAddress()?.ToString() ?? string.Empty),
                    SupportsIPv4 = nic.Supports(NetworkInterfaceComponent.IPv4),
                    SupportsIPv6 = nic.Supports(NetworkInterfaceComponent.IPv6)
                };
                
                try
                {
                    var ipProperties = nic.GetIPProperties();
                    
                    // Get IPv4 addresses
                    interfaceDetails.IPv4Addresses = ipProperties.UnicastAddresses
                        .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                        .Select(a => new IPv4AddressInfo
                        {
                            Address = a.Address,
                            SubnetMask = a.IPv4Mask,
                            PrefixLength = a.PrefixLength,
                            IsDhcpEnabled = ipProperties.GetIPv4Properties()?.IsDhcpEnabled ?? false
                        })
                        .ToList();
                    
                    // Get IPv6 addresses
                    interfaceDetails.IPv6Addresses = ipProperties.UnicastAddresses
                        .Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6)
                        .Select(a => new IPv6AddressInfo
                        {
                            Address = a.Address,
                            PrefixLength = a.PrefixLength
                        })
                        .ToList();
                    
                    // Get gateway addresses
                    interfaceDetails.GatewayAddresses = ipProperties.GatewayAddresses
                        .Select(g => g.Address)
                        .ToList();
                    
                    // Get DNS servers
                    interfaceDetails.DnsServers = ipProperties.DnsAddresses.ToList();
                }
                catch (Exception)
                {
                    // Skip errors in interface properties
                }
                
                result.Add(interfaceDetails);
            }
            
            return result;
        }
        
        /// <summary>
        /// Gets a specific network interface by name
        /// </summary>
        /// <param name="interfaceName">The name of the interface to get</param>
        /// <returns>Interface details or null if not found</returns>
        public InterfaceDetails? GetInterfaceByName(string interfaceName)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                return null;
                
            return GetAllNetworkInterfaces()
                .FirstOrDefault(i => i.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));
        }
        
        /// <summary>
        /// Gets the active network interfaces (operational and with an IPv4 address)
        /// </summary>
        /// <returns>List of active interface details</returns>
        public IEnumerable<InterfaceDetails> GetActiveInterfaces()
        {
            return GetAllNetworkInterfaces()
                .Where(i => i.Status == OperationalStatus.Up && i.IPv4Addresses.Any());
        }
        
        /// <summary>
        /// Gets the primary interface (interface with a default gateway)
        /// </summary>
        /// <returns>The primary interface or null if not found</returns>
        public InterfaceDetails? GetPrimaryInterface()
        {
            return GetActiveInterfaces()
                .FirstOrDefault(i => i.GatewayAddresses.Any());
        }
        
        /// <summary>
        /// Formats a MAC address with colons
        /// </summary>
        /// <param name="macAddress">The raw MAC address string</param>
        /// <returns>Formatted MAC address</returns>
        private string FormatMacAddress(string macAddress)
        {
            if (string.IsNullOrEmpty(macAddress))
                return string.Empty;
                
            var formatted = string.Empty;
            for (var i = 0; i < macAddress.Length; i += 2)
            {
                if (i > 0)
                    formatted += ":";
                    
                formatted += macAddress.Substring(i, 2);
            }
            
            return formatted;
        }
    }
    
    /// <summary>
    /// Contains detailed information about a network interface
    /// </summary>
    public class InterfaceDetails
    {
        /// <summary>
        /// Name of the network interface
        /// </summary>
        public string Name { get; set; } = string.Empty;
        
        /// <summary>
        /// Description of the network interface
        /// </summary>
        public string Description { get; set; } = string.Empty;
        
        /// <summary>
        /// Type of network interface (Ethernet, Wireless, etc.)
        /// </summary>
        public NetworkInterfaceType Type { get; set; }
        
        /// <summary>
        /// Current operational status
        /// </summary>
        public OperationalStatus Status { get; set; }
        
        /// <summary>
        /// Interface speed in bits per second
        /// </summary>
        public long Speed { get; set; }
        
        /// <summary>
        /// MAC address of the interface
        /// </summary>
        public string MacAddress { get; set; } = string.Empty;
        
        /// <summary>
        /// Whether IPv4 is supported
        /// </summary>
        public bool SupportsIPv4 { get; set; }
        
        /// <summary>
        /// Whether IPv6 is supported
        /// </summary>
        public bool SupportsIPv6 { get; set; }
        
        /// <summary>
        /// List of IPv4 addresses assigned to this interface
        /// </summary>
        public List<IPv4AddressInfo> IPv4Addresses { get; set; } = new List<IPv4AddressInfo>();
        
        /// <summary>
        /// List of IPv6 addresses assigned to this interface
        /// </summary>
        public List<IPv6AddressInfo> IPv6Addresses { get; set; } = new List<IPv6AddressInfo>();
        
        /// <summary>
        /// List of gateway addresses
        /// </summary>
        public List<IPAddress> GatewayAddresses { get; set; } = new List<IPAddress>();
        
        /// <summary>
        /// List of DNS servers
        /// </summary>
        public List<IPAddress> DnsServers { get; set; } = new List<IPAddress>();
        
        /// <summary>
        /// Gets the speed in a human-readable format
        /// </summary>
        public string FormattedSpeed
        {
            get
            {
                if (Speed <= 0)
                    return "Unknown";
                    
                if (Speed >= 1_000_000_000)
                    return $"{Speed / 1_000_000_000.0:F2} Gbps";
                    
                if (Speed >= 1_000_000)
                    return $"{Speed / 1_000_000.0:F2} Mbps";
                    
                if (Speed >= 1_000)
                    return $"{Speed / 1_000.0:F2} Kbps";
                    
                return $"{Speed} bps";
            }
        }
    }
    
    /// <summary>
    /// Contains information about an IPv4 address
    /// </summary>
    public class IPv4AddressInfo
    {
        /// <summary>
        /// The IP address
        /// </summary>
        public IPAddress Address { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The subnet mask
        /// </summary>
        public IPAddress SubnetMask { get; set; } = IPAddress.None;
        
        /// <summary>
        /// The CIDR prefix length
        /// </summary>
        public int PrefixLength { get; set; }
        
        /// <summary>
        /// Whether DHCP is enabled for this address
        /// </summary>
        public bool IsDhcpEnabled { get; set; }
        
        /// <summary>
        /// Gets the CIDR notation for this IP address
        /// </summary>
        public string CidrNotation => $"{Address}/{PrefixLength}";
    }
    
    /// <summary>
    /// Contains information about an IPv6 address
    /// </summary>
    public class IPv6AddressInfo
    {
        /// <summary>
        /// The IPv6 address
        /// </summary>
        public IPAddress Address { get; set; } = IPAddress.IPv6None;
        
        /// <summary>
        /// The CIDR prefix length
        /// </summary>
        public int PrefixLength { get; set; }
        
        /// <summary>
        /// Gets the CIDR notation for this IPv6 address
        /// </summary>
        public string CidrNotation => $"{Address}/{PrefixLength}";
    }
}
