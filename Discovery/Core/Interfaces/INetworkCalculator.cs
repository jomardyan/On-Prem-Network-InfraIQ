using System.Net;
using Discovery.Core.Models;

namespace Discovery.Core.Interfaces
{
    /// <summary>
    /// Interface for network calculation operations
    /// </summary>
    public interface INetworkCalculator
    {
        /// <summary>
        /// Calculates network information from CIDR notation
        /// </summary>
        /// <param name="cidr">The CIDR notation (e.g. 192.168.1.0/24)</param>
        /// <returns>Network information object</returns>
        NetworkInfo CalculateNetworkFromCidr(string cidr);
        
        /// <summary>
        /// Calculates a supernet from a list of networks
        /// </summary>
        /// <param name="networks">The list of networks to summarize</param>
        /// <returns>The supernet that encompasses all provided networks</returns>
        NetworkInfo CalculateSupernet(System.Collections.Generic.List<NetworkInfo> networks);
        
        /// <summary>
        /// Calculates subnet information for a given network
        /// </summary>
        /// <param name="networkAddress">The network address</param>
        /// <param name="subnetMask">The subnet mask as a prefix length (0-32)</param>
        /// <returns>Network information with subnet details</returns>
        NetworkInfo CalculateSubnet(IPAddress networkAddress, int subnetMask);
        
        /// <summary>
        /// Divides a network into multiple subnets
        /// </summary>
        /// <param name="baseNetwork">The base network to divide</param>
        /// <param name="subnetCount">The number of subnets needed</param>
        /// <param name="hostsPerSubnet">The minimum hosts per subnet needed</param>
        /// <returns>A list of subnet information</returns>
        System.Collections.Generic.List<NetworkInfo> PlanSubnets(NetworkInfo baseNetwork, int subnetCount, int hostsPerSubnet);
    }
}
