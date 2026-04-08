using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Discovery.Core.Utilities
{
    /// <summary>
    /// Helper class for DNS operations during scanning
    /// </summary>
    public static class DnsLookupHelper
    {
        /// <summary>
        /// Performs a reverse DNS lookup for the given IP address with timeout
        /// </summary>
        /// <param name="ipAddress">The IP address to lookup</param>
        /// <param name="timeoutMs">Timeout in milliseconds (default: 2000ms)</param>
        /// <returns>The hostname if found, empty string if not found or on error</returns>
        public static async Task<string> GetHostnameAsync(IPAddress ipAddress, int timeoutMs = 2000)
        {
            try
            {
                using var cts = new CancellationTokenSource(timeoutMs);
                var dnsTask = Dns.GetHostEntryAsync(ipAddress);
                var timeoutTask = Task.Delay(timeoutMs, cts.Token);
                
                var completedTask = await Task.WhenAny(dnsTask, timeoutTask).ConfigureAwait(false);
                
                if (completedTask == dnsTask)
                {
                    var hostEntry = await dnsTask.ConfigureAwait(false);
                    return hostEntry.HostName ?? string.Empty;
                }
                
                // Timeout occurred
                return string.Empty;
            }
            catch (Exception)
            {
                // Return empty string on any error (timeout, no DNS record, etc.)
                // This ensures scanning continues without interruption
                return string.Empty;
            }
        }

        /// <summary>
        /// Performs a reverse DNS lookup for the given IP address string with timeout
        /// </summary>
        /// <param name="ipAddressString">The IP address as string to lookup</param>
        /// <param name="timeoutMs">Timeout in milliseconds (default: 2000ms)</param>
        /// <returns>The hostname if found, empty string if not found or on error</returns>
        public static async Task<string> GetHostnameAsync(string ipAddressString, int timeoutMs = 2000)
        {
            if (!IPAddress.TryParse(ipAddressString, out var ipAddress))
            {
                return string.Empty;
            }

            return await GetHostnameAsync(ipAddress, timeoutMs).ConfigureAwait(false);
        }
    }
}