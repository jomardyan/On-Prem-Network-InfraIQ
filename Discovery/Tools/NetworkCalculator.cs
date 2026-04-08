using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Numerics;

namespace Discovery.Tools
{
    /// <summary>
    /// Network calculator for IP address, subnet, and CIDR calculations
    /// </summary>
    public static class NetworkCalculator
    {
        /// <summary>
        /// Calculate network information for a given IP address and subnet mask
        /// </summary>
        public static NetworkInfo CalculateNetwork(IPAddress ipAddress, IPAddress subnetMask)
        {
            if (ipAddress.AddressFamily != subnetMask.AddressFamily)
                throw new ArgumentException("IP address and subnet mask must be the same address family");

            var ipBytes = ipAddress.GetAddressBytes();
            var maskBytes = subnetMask.GetAddressBytes();
            
            // Calculate network address
            var networkBytes = new byte[ipBytes.Length];
            for (int i = 0; i < ipBytes.Length; i++)
            {
                networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
            }

            // Calculate broadcast address
            var broadcastBytes = new byte[ipBytes.Length];
            for (int i = 0; i < ipBytes.Length; i++)
            {
                broadcastBytes[i] = (byte)(ipBytes[i] | (~maskBytes[i] & 0xFF));
            }

            var networkAddress = new IPAddress(networkBytes);
            var broadcastAddress = new IPAddress(broadcastBytes);

            // Calculate prefix length
            int prefixLength = CalculatePrefixLength(subnetMask);

            // Calculate total hosts and usable hosts
            int totalBits = ipBytes.Length * 8;
            int hostBits = totalBits - prefixLength;
            long totalHosts = (long)Math.Pow(2, hostBits);
            long usableHosts = Math.Max(0, totalHosts - 2); // Subtract network and broadcast

            // Calculate first and last usable IP
            IPAddress? firstUsableIp = null;
            IPAddress? lastUsableIp = null;

            if (usableHosts > 0)
            {
                firstUsableIp = GetNextIpAddress(networkAddress);
                lastUsableIp = GetPreviousIpAddress(broadcastAddress);
            }

            return new NetworkInfo
            {
                IpAddress = ipAddress,
                SubnetMask = subnetMask,
                NetworkAddress = networkAddress,
                BroadcastAddress = broadcastAddress,
                FirstUsableIp = firstUsableIp,
                LastUsableIp = lastUsableIp,
                PrefixLength = prefixLength,
                TotalHosts = totalHosts,
                UsableHosts = usableHosts,
                NetworkClass = DetermineNetworkClass(ipAddress),
                IsPrivate = IsPrivateIpAddress(ipAddress)
            };
        }

        /// <summary>
        /// Calculate network information from CIDR notation
        /// </summary>
        public static NetworkInfo CalculateNetworkFromCidr(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2)
                throw new ArgumentException("Invalid CIDR notation");

            if (!IPAddress.TryParse(parts[0], out var ipAddress))
                throw new ArgumentException("Invalid IP address in CIDR");

            if (!int.TryParse(parts[1], out var prefixLength))
                throw new ArgumentException("Invalid prefix length in CIDR");

            var subnetMask = CreateSubnetMask(prefixLength, ipAddress.AddressFamily);
            return CalculateNetwork(ipAddress, subnetMask);
        }

        /// <summary>
        /// Convert subnet mask to CIDR prefix length
        /// </summary>
        public static int CalculatePrefixLength(IPAddress subnetMask)
        {
            var maskBytes = subnetMask.GetAddressBytes();
            int prefixLength = 0;

            foreach (byte b in maskBytes)
            {
                prefixLength += CountBits(b);
            }

            return prefixLength;
        }

        /// <summary>
        /// Create subnet mask from prefix length
        /// </summary>
        public static IPAddress CreateSubnetMask(int prefixLength, System.Net.Sockets.AddressFamily addressFamily)
        {
            int totalBits = addressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            
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

        /// <summary>
        /// Generate all IP addresses in a subnet
        /// </summary>
        public static IEnumerable<IPAddress> GetIpAddressesInSubnet(NetworkInfo networkInfo, bool includeNetworkAndBroadcast = false)
        {
            var result = new List<IPAddress>();
            
            if (networkInfo.UsableHosts == 0)
                return result;

            var current = includeNetworkAndBroadcast ? networkInfo.NetworkAddress : networkInfo.FirstUsableIp;
            var end = includeNetworkAndBroadcast ? networkInfo.BroadcastAddress : networkInfo.LastUsableIp;

            if (current == null || end == null)
                return result;

            while (CompareIpAddresses(current, end) <= 0)
            {
                result.Add(current);
                current = GetNextIpAddress(current);
                
                // Prevent infinite loop for very large subnets
                if (result.Count > 100000)
                    break;
            }

            return result;
        }

        /// <summary>
        /// Check if an IP address belongs to a specific subnet
        /// </summary>
        public static bool IsIpInSubnet(IPAddress ipAddress, NetworkInfo networkInfo)
        {
            if (ipAddress.AddressFamily != networkInfo.NetworkAddress.AddressFamily)
                return false;

            var ipBytes = ipAddress.GetAddressBytes();
            var networkBytes = networkInfo.NetworkAddress.GetAddressBytes();
            var maskBytes = networkInfo.SubnetMask.GetAddressBytes();

            for (int i = 0; i < ipBytes.Length; i++)
            {
                if ((ipBytes[i] & maskBytes[i]) != networkBytes[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Calculate supernet (route summarization)
        /// </summary>
        public static NetworkInfo? CalculateSupernet(IEnumerable<NetworkInfo> subnets)
        {
            var subnetList = subnets.ToList();
            if (!subnetList.Any())
                return null;

            // All subnets must be the same address family
            var addressFamily = subnetList.First().IpAddress.AddressFamily;
            if (!subnetList.All(s => s.IpAddress.AddressFamily == addressFamily))
                return null;

            // Find the smallest network that contains all subnets
            var allNetworkAddresses = subnetList.Select(s => s.NetworkAddress).ToList();
            var minIp = allNetworkAddresses.Min(ip => IpToNumber(ip));
            var maxNetwork = subnetList.OrderByDescending(s => s.BroadcastAddress, new IpAddressComparer()).First();
            var maxIp = IpToNumber(maxNetwork.BroadcastAddress);

            // Calculate the required prefix length
            var range = maxIp - minIp + 1;
            var hostBits = (int)Math.Ceiling(Math.Log2((double)range));
            var totalBits = addressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            var prefixLength = totalBits - hostBits;

            var supernetMask = CreateSubnetMask(prefixLength, addressFamily);
            var firstNetworkAddress = NumberToIp(minIp, addressFamily);

            return CalculateNetwork(firstNetworkAddress, supernetMask);
        }

        #region Private Helper Methods

        private static int CountBits(byte value)
        {
            int count = 0;
            while (value != 0)
            {
                count++;
                value &= (byte)(value - 1);
            }
            return count;
        }

        private static string DetermineNetworkClass(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
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

        private static bool IsPrivateIpAddress(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;

            var bytes = ipAddress.GetAddressBytes();
            
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

        private static IPAddress GetNextIpAddress(IPAddress ipAddress)
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

        private static IPAddress GetPreviousIpAddress(IPAddress ipAddress)
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

        private static int CompareIpAddresses(IPAddress ip1, IPAddress ip2)
        {
            if (ip1.AddressFamily != ip2.AddressFamily)
                return ip1.AddressFamily.CompareTo(ip2.AddressFamily);

            var bytes1 = ip1.GetAddressBytes();
            var bytes2 = ip2.GetAddressBytes();

            for (int i = 0; i < bytes1.Length; i++)
            {
                int result = bytes1[i].CompareTo(bytes2[i]);
                if (result != 0)
                    return result;
            }

            return 0;
        }

        private static BigInteger IpToNumber(IPAddress ipAddress)
        {
            var bytes = ipAddress.GetAddressBytes();
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            
            // Add a zero byte to ensure positive number
            var extendedBytes = new byte[bytes.Length + 1];
            Array.Copy(bytes, 0, extendedBytes, 1, bytes.Length);
            
            return new BigInteger(extendedBytes);
        }

        private static IPAddress NumberToIp(BigInteger number, System.Net.Sockets.AddressFamily addressFamily)
        {
            int byteCount = addressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 4 : 16;
            var bytes = number.ToByteArray();
            
            if (bytes.Length > byteCount + 1)
                throw new ArgumentException("Number too large for IP address");

            var ipBytes = new byte[byteCount];
            int copyLength = Math.Min(bytes.Length, byteCount);
            Array.Copy(bytes, ipBytes, copyLength);
            
            if (BitConverter.IsLittleEndian)
                Array.Reverse(ipBytes);

            return new IPAddress(ipBytes);
        }

        #endregion
    }

    /// <summary>
    /// Network information data structure
    /// </summary>
    public class NetworkInfo
    {
        public IPAddress IpAddress { get; set; } = IPAddress.None;
        public IPAddress SubnetMask { get; set; } = IPAddress.None;
        public IPAddress NetworkAddress { get; set; } = IPAddress.None;
        public IPAddress BroadcastAddress { get; set; } = IPAddress.None;
        public IPAddress? FirstUsableIp { get; set; }
        public IPAddress? LastUsableIp { get; set; }
        public int PrefixLength { get; set; }
        public long TotalHosts { get; set; }
        public long UsableHosts { get; set; }
        public string NetworkClass { get; set; } = string.Empty;
        public bool IsPrivate { get; set; }
    }

    /// <summary>
    /// IP Address comparer for sorting
    /// </summary>
    public class IpAddressComparer : IComparer<IPAddress>
    {
        public int Compare(IPAddress? x, IPAddress? y)
        {
            if (x == null && y == null) return 0;
            if (x == null) return -1;
            if (y == null) return 1;

            if (x.AddressFamily != y.AddressFamily)
                return x.AddressFamily.CompareTo(y.AddressFamily);

            var bytes1 = x.GetAddressBytes();
            var bytes2 = y.GetAddressBytes();

            for (int i = 0; i < bytes1.Length; i++)
            {
                int result = bytes1[i].CompareTo(bytes2[i]);
                if (result != 0)
                    return result;
            }

            return 0;
        }
    }
}
