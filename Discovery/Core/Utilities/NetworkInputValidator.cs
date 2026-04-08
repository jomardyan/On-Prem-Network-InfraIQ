using System;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Discovery.Core.Utilities
{
    /// <summary>
    /// Utility class for validating network-related inputs
    /// </summary>
    public static class NetworkInputValidator
    {
        private static readonly Regex CidrRegex = new(@"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$", RegexOptions.Compiled);
        private static readonly Regex PortRangeRegex = new(@"^(\d+(-\d+)?)(,\d+(-\d+)?)*$", RegexOptions.Compiled);
        private static readonly Regex DomainRegex = new(@"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$", RegexOptions.Compiled);

        /// <summary>
        /// Validates if the provided string is a valid IP address
        /// </summary>
        /// <param name="ipAddress">IP address to validate</param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool IsValidIpAddress(string? ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            // First check with IPAddress.TryParse
            if (!IPAddress.TryParse(ipAddress, out var ip))
                return false;

            // Additional validation to ensure it's a proper IPv4 address
            var parts = ipAddress.Split('.');
            if (parts.Length != 4)
                return false;

            foreach (var part in parts)
            {
                if (!int.TryParse(part, out int num) || num < 0 || num > 255)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Validates if the provided string is a valid CIDR notation
        /// </summary>
        /// <param name="cidr">CIDR notation to validate</param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool IsValidCidr(string? cidr)
        {
            if (string.IsNullOrWhiteSpace(cidr))
                return false;

            return CidrRegex.IsMatch(cidr);
        }

        /// <summary>
        /// Validates if the provided string is a valid port range specification
        /// </summary>
        /// <param name="portRange">Port range to validate (e.g., "80,443,8080-8090")</param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool IsValidPortRange(string? portRange)
        {
            if (string.IsNullOrWhiteSpace(portRange))
                return false;

            if (!PortRangeRegex.IsMatch(portRange))
                return false;

            // Additional validation for port numbers
            var parts = portRange.Split(',');
            foreach (var part in parts)
            {
                if (part.Contains('-'))
                {
                    var rangeParts = part.Split('-');
                    if (rangeParts.Length != 2)
                        return false;

                    if (!int.TryParse(rangeParts[0], out int start) || !int.TryParse(rangeParts[1], out int end))
                        return false;

                    if (start < 1 || start > 65535 || end < 1 || end > 65535 || start > end)
                        return false;
                }
                else
                {
                    if (!int.TryParse(part, out int port) || port < 1 || port > 65535)
                        return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Validates if the provided string is a valid domain name
        /// </summary>
        /// <param name="domain">Domain name to validate</param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool IsValidDomain(string? domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return false;

            if (domain.Length > 255)
                return false;

            // Additional checks for common invalid patterns
            if (domain.StartsWith('.') || domain.EndsWith('.') || domain.Contains(".."))
                return false;

            // Check if it's a valid domain name (not just containing invalid characters)
            try
            {
                // Simple check - domain must contain at least one letter and valid characters
                if (!domain.Any(char.IsLetter))
                    return false;

                // For a valid domain, we need at least one dot unless it's a TLD
                // But even TLDs in practice have more specific requirements
                // For our purposes, let's require at least one dot for practical domains
                if (!domain.Contains('.'))
                    return false;

                return DomainRegex.IsMatch(domain);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates if the provided string is a valid hostname or IP address
        /// </summary>
        /// <param name="target">Target to validate</param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool IsValidTarget(string? target)
        {
            return IsValidIpAddress(target) || IsValidDomain(target);
        }

        /// <summary>
        /// Checks if an IP address is in a private network range
        /// </summary>
        /// <param name="ipAddress">IP address to check</param>
        /// <returns>True if private, false otherwise</returns>
        public static bool IsPrivateIpAddress(string ipAddress)
        {
            if (!IsValidIpAddress(ipAddress))
                return false;

            var ip = IPAddress.Parse(ipAddress);
            var bytes = ip.GetAddressBytes();

            // 10.0.0.0/8
            if (bytes[0] == 10)
                return true;

            // 172.16.0.0/12
            if (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31))
                return true;

            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
                return true;

            // 127.0.0.0/8 (loopback)
            if (bytes[0] == 127)
                return true;

            return false;
        }

        /// <summary>
        /// Provides user-friendly error message for invalid inputs
        /// </summary>
        /// <param name="input">The input that failed validation</param>
        /// <param name="inputType">Type of input (IP, CIDR, Port, etc.)</param>
        /// <returns>Formatted error message</returns>
        public static string GetValidationErrorMessage(string input, string inputType)
        {
            return inputType.ToLower() switch
            {
                "ip" => $"'{input}' is not a valid IP address. Please use format like '192.168.1.1'",
                "cidr" => $"'{input}' is not valid CIDR notation. Please use format like '192.168.1.0/24'",
                "port" => $"'{input}' is not a valid port specification. Use single ports (80) or ranges (80-90) separated by commas",
                "domain" => $"'{input}' is not a valid domain name. Please use format like 'example.com'",
                "target" => $"'{input}' is not a valid IP address or domain name",
                _ => $"'{input}' is not a valid {inputType}"
            };
        }
    }
}