using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Spectre.Console;

namespace Discovery.Services.Discovery
{
    /// <summary>
    /// Implements ping sweep functionality to discover live hosts on a network
    /// </summary>
    public class PingSweeper
    {
        private readonly int _timeout;
        private readonly int _maxConcurrency;

        public PingSweeper(int timeout = 1000, int maxConcurrency = 50)
        {
            _timeout = timeout;
            _maxConcurrency = maxConcurrency;
        }

        /// <summary>
        /// Performs a ping sweep on a CIDR network
        /// </summary>
        /// <param name="cidrNotation">The CIDR notation (e.g. 192.168.1.0/24)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of alive hosts</returns>
        public async Task<List<string>> PingSweepCidrAsync(string cidrNotation, CancellationToken cancellationToken = default)
        {
            var aliveHosts = new List<string>();
            
            if (!TryParseCidr(cidrNotation, out var networkAddress, out var subnetMask) || networkAddress == null)
            {
                AnsiConsole.MarkupLine("[red]❌ Invalid CIDR notation.[/]");
                return aliveHosts;
            }

            await AnsiConsole.Progress()
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn(),
                })
                .StartAsync(async ctx =>
                {
                    var networkBytes = networkAddress.GetAddressBytes();
                    uint network_uint = (uint)networkBytes[0] << 24 | (uint)networkBytes[1] << 16 | (uint)networkBytes[2] << 8 | networkBytes[3];
                    
                    uint mask = 0xFFFFFFFF << (32 - subnetMask);
                    network_uint = network_uint & mask;
                    
                    uint hostBits = (uint)(32 - subnetMask);
                    uint totalHosts = (uint)(Math.Pow(2, hostBits) - 2);
                    
                    var pingTask = ctx.AddTask("[green]📡 Pinging hosts[/]");
                    pingTask.MaxValue = totalHosts;
                    
                    var semaphore = new SemaphoreSlim(_maxConcurrency);
                    var tasks = new List<Task>();
                    
                    for (uint i = 1; i <= totalHosts; i++)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            break;
                            
                        uint currentIp = network_uint + i;
                        var ipBytes = new byte[4];
                        ipBytes[0] = (byte)(currentIp >> 24);
                        ipBytes[1] = (byte)(currentIp >> 16);
                        ipBytes[2] = (byte)(currentIp >> 8);
                        ipBytes[3] = (byte)currentIp;
                        
                        string ipAddress = new IPAddress(ipBytes).ToString();
                        
                        await semaphore.WaitAsync(cancellationToken);
                        tasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                bool isAlive = await PingHostAsync(ipAddress);
                                if (isAlive)
                                {
                                    lock (aliveHosts)
                                    {
                                        aliveHosts.Add(ipAddress);
                                    }
                                }
                            }
                            finally
                            {
                                pingTask.Increment(1);
                                semaphore.Release();
                            }
                        }, cancellationToken));
                    }
                    
                    try
                    {
                        await Task.WhenAll(tasks);
                    }
                    catch (OperationCanceledException)
                    {
                        // Expected when cancellation is requested
                    }
                });

            return aliveHosts;
        }

        /// <summary>
        /// Performs a ping sweep on an IP range
        /// </summary>
        /// <param name="baseIp">The base IP (e.g. 192.168.1.)</param>
        /// <param name="startRange">Start of the range</param>
        /// <param name="endRange">End of the range</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of alive hosts</returns>
        public async Task<List<string>> PingSweepRangeAsync(string baseIp, int startRange, int endRange, CancellationToken cancellationToken = default)
        {
            var aliveHosts = new List<string>();
            
            if (!baseIp.EndsWith("."))
            {
                baseIp += ".";
            }

            await AnsiConsole.Progress()
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn(),
                })
                .StartAsync(async ctx =>
                {
                    var pingTask = ctx.AddTask("[green]📡 Pinging hosts[/]");
                    pingTask.MaxValue = endRange - startRange + 1;
                    
                    var semaphore = new SemaphoreSlim(_maxConcurrency);
                    var tasks = new List<Task>();
                    
                    for (int i = startRange; i <= endRange; i++)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            break;
                            
                        string ipAddress = baseIp + i;
                        
                        await semaphore.WaitAsync(cancellationToken);
                        tasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                bool isAlive = await PingHostAsync(ipAddress);
                                if (isAlive)
                                {
                                    lock (aliveHosts)
                                    {
                                        aliveHosts.Add(ipAddress);
                                    }
                                }
                            }
                            finally
                            {
                                pingTask.Increment(1);
                                semaphore.Release();
                            }
                        }, cancellationToken));
                    }
                    
                    try
                    {
                        await Task.WhenAll(tasks);
                    }
                    catch (OperationCanceledException)
                    {
                        // Expected when cancellation is requested
                    }
                });

            return aliveHosts;
        }

        /// <summary>
        /// Pings a single host
        /// </summary>
        /// <param name="hostNameOrAddress">The hostname or IP address to ping</param>
        /// <returns>True if host is alive, otherwise false</returns>
        public async Task<bool> PingHostAsync(string hostNameOrAddress)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(hostNameOrAddress, _timeout);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                // Handle network errors or host unreachable
                return false;
            }
        }

        /// <summary>
        /// Gets detailed ping information for a host
        /// </summary>
        /// <param name="hostNameOrAddress">The hostname or IP address to ping</param>
        /// <param name="count">Number of pings to send</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of ping results</returns>
        public async Task<List<PingReply>> GetDetailedPingAsync(string hostNameOrAddress, int count = 4, CancellationToken cancellationToken = default)
        {
            var results = new List<PingReply>();
            
            try
            {
                using var ping = new Ping();
                
                for (int i = 0; i < count; i++)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;
                        
                    try
                    {
                        var reply = await ping.SendPingAsync(hostNameOrAddress, _timeout);
                        results.Add(reply);
                        
                        // Short delay between pings
                        await Task.Delay(100, cancellationToken);
                    }
                    catch
                    {
                        // Just ignore individual ping failures
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error pinging {hostNameOrAddress}: {ex.Message}[/]");
            }
            
            return results;
        }

        /// <summary>
        /// Parses CIDR notation
        /// </summary>
        private bool TryParseCidr(string cidr, out IPAddress? networkAddress, out int subnetMask)
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
    }
}
