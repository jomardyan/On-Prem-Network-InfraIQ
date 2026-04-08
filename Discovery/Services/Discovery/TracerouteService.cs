using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;

namespace Discovery.Services.Discovery
{
    /// <summary>
    /// Implements traceroute functionality to trace the path to a destination
    /// </summary>
    public class TracerouteService
    {
        private readonly int _timeout;
        private readonly int _maxHops;
        private readonly int _pingAttempts;

        public TracerouteService(int timeout = 3000, int maxHops = 30, int pingAttempts = 3)
        {
            _timeout = timeout;
            _maxHops = maxHops;
            _pingAttempts = pingAttempts;
        }

        /// <summary>
        /// Performs a traceroute to the specified destination
        /// </summary>
        /// <param name="destination">The hostname or IP address to trace</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>A list of hops with timing information</returns>
        public async Task<List<TracerouteHop>> PerformTracerouteAsync(string destination, CancellationToken cancellationToken = default)
        {
            var result = new List<TracerouteHop>();
            var dnsLookup = new DnsLookupService();

            // Resolve hostname to IP if needed
            IPAddress? destinationIp;
            try
            {
                if (!IPAddress.TryParse(destination, out destinationIp))
                {
                    var hostEntry = await Dns.GetHostEntryAsync(destination, cancellationToken);
                    if (hostEntry.AddressList.Length > 0)
                    {
                        destinationIp = hostEntry.AddressList[0];
                    }
                    else
                    {
                        throw new Exception($"Could not resolve hostname {destination}");
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error resolving destination: {ex.Message}[/]");
                return result;
            }

            await AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Dots)
                .StartAsync($"Tracing route to {destination} [{destinationIp}]...", async ctx =>
                {
                    for (int ttl = 1; ttl <= _maxHops; ttl++)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            break;

                        ctx.Status($"Hop {ttl}/{_maxHops}: Sending packets...");

                        var hopResult = await TraceHopAsync(destinationIp, ttl, cancellationToken);
                        
                        // Try to resolve the IP to a hostname
                        if (hopResult.Success && !string.IsNullOrEmpty(hopResult.Address))
                        {
                            try
                            {
                                var hopIp = IPAddress.Parse(hopResult.Address);
                                var hostname = await dnsLookup.ReverseDnsLookupAsync(hopIp.ToString());
                                if (!string.IsNullOrEmpty(hostname))
                                {
                                    hopResult.Hostname = hostname;
                                }
                            }
                            catch
                            {
                                // Ignore reverse DNS lookup failures
                            }
                        }
                        
                        result.Add(hopResult);
                        
                        // If we've reached the destination, we can stop
                        if (hopResult.Success && hopResult.Address == destinationIp.ToString())
                            break;
                        
                        // Add a small delay between hops to avoid overwhelming the network
                        await Task.Delay(100, cancellationToken);
                    }
                });

            return result;
        }

        /// <summary>
        /// Traces a single hop with the specified TTL
        /// </summary>
        /// <param name="destination">Destination IP address</param>
        /// <param name="ttl">Time-to-live value for this hop</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Information about the hop</returns>
        private async Task<TracerouteHop> TraceHopAsync(IPAddress destination, int ttl, CancellationToken cancellationToken)
        {
            var result = new TracerouteHop
            {
                HopNumber = ttl
            };
            
            var pingTimes = new List<long>();
            bool success = false;
            string? hopAddress = null;
            
            using var ping = new Ping();
            var options = new PingOptions(ttl, true);
            byte[] buffer = Encoding.ASCII.GetBytes(new string('a', 32));
            
            for (int attempt = 0; attempt < _pingAttempts; attempt++)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;
                    
                try
                {
                    var reply = await ping.SendPingAsync(destination, _timeout, buffer, options);
                    
                    if (reply.Status == IPStatus.Success || reply.Status == IPStatus.TtlExpired)
                    {
                        success = true;
                        pingTimes.Add(reply.RoundtripTime);
                        
                        // Get the address of the router/host that replied
                        if (string.IsNullOrEmpty(hopAddress) && reply.Address != null)
                        {
                            hopAddress = reply.Address.ToString();
                        }
                    }
                }
                catch
                {
                    // Ignore exceptions and continue with next attempt
                }
                
                // Add a small delay between ping attempts
                if (attempt < _pingAttempts - 1)
                {
                    await Task.Delay(100, cancellationToken);
                }
            }
            
            result.Success = success;
            result.Address = hopAddress ?? string.Empty;
            
            if (pingTimes.Count > 0)
            {
                result.MinTime = pingTimes.Min();
                result.MaxTime = pingTimes.Max();
                result.AvgTime = (long)pingTimes.Average();
            }
            
            return result;
        }
    }

    /// <summary>
    /// Represents a single hop in a traceroute
    /// </summary>
    public class TracerouteHop
    {
        /// <summary>
        /// The hop number (TTL value)
        /// </summary>
        public int HopNumber { get; set; }
        
        /// <summary>
        /// Whether the hop was successfully traced
        /// </summary>
        public bool Success { get; set; }
        
        /// <summary>
        /// The IP address of the hop
        /// </summary>
        public string Address { get; set; } = string.Empty;
        
        /// <summary>
        /// The hostname of the hop (if available)
        /// </summary>
        public string Hostname { get; set; } = string.Empty;
        
        /// <summary>
        /// The minimum round-trip time in milliseconds
        /// </summary>
        public long MinTime { get; set; }
        
        /// <summary>
        /// The maximum round-trip time in milliseconds
        /// </summary>
        public long MaxTime { get; set; }
        
        /// <summary>
        /// The average round-trip time in milliseconds
        /// </summary>
        public long AvgTime { get; set; }
    }
}
