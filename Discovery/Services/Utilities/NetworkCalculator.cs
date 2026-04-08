using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;

namespace Discovery.Services.Utilities
{
    /// <summary>
    /// Utility service for IP address, subnet, and CIDR calculations
    /// </summary>
    public class NetworkCalculator : INetworkCalculator
    {
        /// <summary>
        /// Calculates network information from CIDR notation
        /// </summary>
        /// <param name="cidr">The CIDR notation (e.g. 192.168.1.0/24)</param>
        /// <returns>Network information object</returns>
        public NetworkInfo CalculateNetworkFromCidr(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2)
                throw new ArgumentException("Invalid CIDR notation");

            if (!IPAddress.TryParse(parts[0], out var ipAddress))
                throw new ArgumentException("Invalid IP address in CIDR");

            if (!int.TryParse(parts[1], out var prefixLength))
                throw new ArgumentException("Invalid prefix length in CIDR");

            var subnetMask = CreateSubnetMask(prefixLength, ipAddress.AddressFamily);
            return CalculateSubnet(ipAddress, prefixLength);
        }

        /// <summary>
        /// Calculates a supernet from a list of networks
        /// </summary>
        /// <param name="networks">The list of networks to summarize</param>
        /// <returns>The supernet that encompasses all provided networks</returns>
        public NetworkInfo CalculateSupernet(List<NetworkInfo> networks)
        {
            if (networks == null || !networks.Any())
                throw new ArgumentException("No networks provided");

            // Ensure all networks are the same address family
            var addressFamily = GetAddressFamily(networks[0].NetworkAddress);
            if (networks.Any(n => GetAddressFamily(n.NetworkAddress) != addressFamily))
                throw new ArgumentException("All networks must be of the same address family (IPv4 or IPv6)");

            // Find the smallest and largest addresses in the networks
            BigInteger minIp = new BigInteger(uint.MaxValue);
            BigInteger maxIp = BigInteger.Zero;

            foreach (var network in networks)
            {
                var networkValue = IpToNumber(network.NetworkAddress);
                var broadcastValue = IpToNumber(network.BroadcastAddress);
                
                if (networkValue < minIp) minIp = networkValue;
                if (broadcastValue > maxIp) maxIp = broadcastValue;
            }

            // Calculate the required prefix length
            BigInteger range = maxIp - minIp + 1;
            int hostBits = (int)Math.Ceiling(BigInteger.Log(range, 2));
            int totalBits = addressFamily == AddressFamily.InterNetwork ? 32 : 128;
            int prefixLength = Math.Max(0, totalBits - hostBits);

            // Create the supernet
            IPAddress networkAddress = NumberToIp(minIp, addressFamily);
            return CalculateSubnet(networkAddress, prefixLength);
        }

        /// <summary>
        /// Calculates subnet information for a given network
        /// </summary>
        /// <param name="networkAddress">The network address</param>
        /// <param name="subnetMask">The subnet mask as a prefix length (0-32)</param>
        /// <returns>Network information with subnet details</returns>
        public NetworkInfo CalculateSubnet(IPAddress networkAddress, int subnetMask)
        {
            if (networkAddress == null)
                throw new ArgumentNullException(nameof(networkAddress));

            int totalBits = networkAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            
            if (subnetMask < 0 || subnetMask > totalBits)
                throw new ArgumentException($"Prefix length must be between 0 and {totalBits}");

            // Calculate subnet mask as IPAddress
            IPAddress subnetMaskIp = CreateSubnetMask(subnetMask, networkAddress.AddressFamily);

            // Calculate wildcard mask (inverse of subnet mask)
            byte[] maskBytes = subnetMaskIp.GetAddressBytes();
            byte[] wildcardBytes = new byte[maskBytes.Length];
            for (int i = 0; i < maskBytes.Length; i++)
            {
                wildcardBytes[i] = (byte)~maskBytes[i];
            }

            IPAddress wildcardMask = new IPAddress(wildcardBytes);

            // Calculate network address (ensure it's properly masked)
            byte[] ipBytes = networkAddress.GetAddressBytes();
            byte[] networkBytes = new byte[ipBytes.Length];
            for (int i = 0; i < ipBytes.Length; i++)
            {
                networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
            }

            IPAddress maskedNetwork = new IPAddress(networkBytes);

            // Calculate broadcast address
            byte[] broadcastBytes = new byte[ipBytes.Length];
            for (int i = 0; i < ipBytes.Length; i++)
            {
                broadcastBytes[i] = (byte)(networkBytes[i] | wildcardBytes[i]);
            }

            IPAddress broadcastAddress = new IPAddress(broadcastBytes);

            // Calculate usable IPs
            int hostBits = totalBits - subnetMask;
            uint totalHosts = hostBits >= 31 ? 0 : (uint)Math.Pow(2, hostBits);
            uint usableHosts = hostBits <= 1 ? totalHosts : totalHosts - 2; // Subtract network and broadcast for normal subnets

            // Calculate first and last usable IP
            IPAddress firstUsableIp = usableHosts > 0
                ? GetNextIpAddress(maskedNetwork)
                : maskedNetwork;
                
            IPAddress lastUsableIp = usableHosts > 0
                ? GetPreviousIpAddress(broadcastAddress)
                : broadcastAddress;

            return new NetworkInfo
            {
                IpAddress = networkAddress, // Use the input network address as the IP address
                NetworkAddress = maskedNetwork,
                BroadcastAddress = broadcastAddress,
                PrefixLength = subnetMask,
                SubnetMask = subnetMaskIp,
                WildcardMask = wildcardMask,
                FirstUsableIp = firstUsableIp,
                LastUsableIp = lastUsableIp,
                TotalHosts = (long)totalHosts,
                UsableHosts = (long)usableHosts,
                NetworkClass = DetermineNetworkClass(networkAddress),
                IsPrivate = IsPrivateIpAddress(networkAddress)
            };
        }

        /// <summary>
        /// Divides a network into multiple subnets
        /// </summary>
        /// <param name="baseNetwork">The base network to divide</param>
        /// <param name="subnetCount">The number of subnets needed</param>
        /// <param name="hostsPerSubnet">The minimum hosts per subnet needed</param>
        /// <returns>A list of subnet information</returns>
        public List<NetworkInfo> PlanSubnets(NetworkInfo baseNetwork, int subnetCount, int hostsPerSubnet)
        {
            if (baseNetwork == null)
                throw new ArgumentNullException(nameof(baseNetwork));
            
            if (subnetCount <= 0)
                throw new ArgumentException("Subnet count must be greater than zero");
                
            if (hostsPerSubnet < 0)
                throw new ArgumentException("Hosts per subnet must be zero or greater");

            int totalBits = baseNetwork.NetworkAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            
            // Calculate required bits for subnets
            int subnetsRequiredBits = (int)Math.Ceiling(Math.Log(subnetCount, 2));
            
            // Calculate required bits for hosts
            int hostsRequiredBits = hostsPerSubnet <= 2
                ? 1
                : (int)Math.Ceiling(Math.Log(hostsPerSubnet + 2, 2)); // +2 for network and broadcast
            
            // Calculate new prefix length for subnets
            int newPrefixLength = baseNetwork.PrefixLength + subnetsRequiredBits;
            
            // Check if we have enough bits
            if (newPrefixLength + hostsRequiredBits > totalBits)
                throw new ArgumentException("Not enough address space for the requested subnet configuration");

            List<NetworkInfo> subnets = new List<NetworkInfo>();
            
            // Calculate the first subnet's network address (same as base network)
            BigInteger baseIpValue = this.IpToNumber(baseNetwork.NetworkAddress);
            
            // Calculate subnet size
            int subnetBits = totalBits - newPrefixLength;
            BigInteger subnetSize = BigInteger.Pow(2, subnetBits);
            
            // Generate each subnet
            for (int i = 0; i < subnetCount; i++)
            {
                BigInteger subnetIpValue = baseIpValue + (i * subnetSize);
                IPAddress subnetIp = this.NumberToIp(subnetIpValue, baseNetwork.NetworkAddress.AddressFamily);
                
                subnets.Add(CalculateSubnet(subnetIp, newPrefixLength));
            }
            
            return subnets;
        }

        #region Private Helper Methods

        private IPAddress CreateSubnetMask(int prefixLength, AddressFamily addressFamily)
        {
            int totalBits = addressFamily == AddressFamily.InterNetwork ? 32 : 128;
            
            if (prefixLength < 0 || prefixLength > totalBits)
                throw new ArgumentException($"Prefix length must be between 0 and {totalBits}");

            int bytes = totalBits / 8;
            var maskBytes = new byte[bytes];

            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            // Set full bytes to 255
            for (int i = 0; i < fullBytes; i++)
            {
                maskBytes[i] = 0xFF;
            }

            // Set partial byte
            if (remainingBits > 0 && fullBytes < bytes)
            {
                maskBytes[fullBytes] = (byte)(0xFF << (8 - remainingBits));
            }

            return new IPAddress(maskBytes);
        }

        private IPAddress GetNextIpAddress(IPAddress ipAddress)
        {
            var bytes = ipAddress.GetAddressBytes();
            
            // Add 1 to the IP address
            for (int i = bytes.Length - 1; i >= 0; i--)
            {
                if (bytes[i] < 255)
                {
                    bytes[i]++;
                    break;
                }

                bytes[i] = 0;
            }

            return new IPAddress(bytes);
        }

        private IPAddress GetPreviousIpAddress(IPAddress ipAddress)
        {
            var bytes = ipAddress.GetAddressBytes();
            
            // Subtract 1 from the IP address
            for (int i = bytes.Length - 1; i >= 0; i--)
            {
                if (bytes[i] > 0)
                {
                    bytes[i]--;
                    break;
                }

                bytes[i] = 255;
            }

            return new IPAddress(bytes);
        }

        private BigInteger IpToNumber(IPAddress ipAddress)
        {
            var bytes = ipAddress.GetAddressBytes();
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            
            // Add a zero byte to ensure positive number
            var extendedBytes = new byte[bytes.Length + 1];
            Array.Copy(bytes, 0, extendedBytes, 1, bytes.Length);
            
            return new BigInteger(extendedBytes);
        }

        private IPAddress NumberToIp(BigInteger number, AddressFamily addressFamily)
        {
            int byteCount = addressFamily == AddressFamily.InterNetwork ? 4 : 16;
            var bytes = number.ToByteArray();
            
            if (bytes.Length > byteCount + 1)
                throw new ArgumentException("Number too large for IP address");

            var ipBytes = new byte[byteCount];
            int copyLength = Math.Min(bytes.Length, byteCount);
            Array.Copy(
                bytes,
                Math.Max(0, bytes.Length - byteCount),
                ipBytes,
                Math.Max(0, byteCount - bytes.Length),
                Math.Min(bytes.Length, byteCount));
            
            if (BitConverter.IsLittleEndian)
                Array.Reverse(ipBytes);

            return new IPAddress(ipBytes);
        }

        private AddressFamily GetAddressFamily(IPAddress ipAddress)
        {
            return ipAddress?.AddressFamily ?? AddressFamily.InterNetwork;
        }

        private string DetermineNetworkClass(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily != AddressFamily.InterNetwork)
                return "IPv6";

            var firstOctet = ipAddress.GetAddressBytes()[0];

            return firstOctet switch
            {
                >= 1 and <= 126 => "Class A",
                >= 128 and <= 191 => "Class B", 
                >= 192 and <= 223 => "Class C",
                >= 224 and <= 239 => "Class D (Multicast)",
                >= 240 and <= 255 => "Class E (Reserved)",
                _ => "Unknown"
            };
        }

        private bool IsPrivateIpAddress(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily != AddressFamily.InterNetwork)
                return false;

            var bytes = ipAddress.GetAddressBytes();
            
            // Check for private IP ranges
            // 10.0.0.0/8
            if (bytes[0] == 10)
                return true;
                
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                return true;
                
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
                return true;

            return false;
        }

        #endregion
    }
}
