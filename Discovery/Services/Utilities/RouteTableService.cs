using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Discovery.Services.Utilities
{
    /// <summary>
    /// Service for retrieving and analyzing the system routing table
    /// </summary>
    public class RouteTableService
    {
        /// <summary>
        /// Gets the routing table from the system
        /// </summary>
        /// <returns>A collection of route information</returns>
        public async Task<IEnumerable<RouteInfo>> GetRoutingTable()
        {
            string output = await ExecuteRouteCommand();
            return ParseRouteOutput(output);
        }
        
        /// <summary>
        /// Gets all routes for a specific destination network
        /// </summary>
        /// <param name="destination">The destination network to filter by</param>
        /// <returns>Routes that match the destination</returns>
        public async Task<IEnumerable<RouteInfo>> GetRoutesForDestination(string destination)
        {
            if (string.IsNullOrWhiteSpace(destination))
                return new List<RouteInfo>();
                
            var routes = await GetRoutingTable();
            return routes.Where(r => r.Destination.Contains(destination));
        }
        
        /// <summary>
        /// Gets all routes for a specific gateway
        /// </summary>
        /// <param name="gateway">The gateway to filter by</param>
        /// <returns>Routes that use the specified gateway</returns>
        public async Task<IEnumerable<RouteInfo>> GetRoutesViaGateway(string gateway)
        {
            if (string.IsNullOrWhiteSpace(gateway))
                return new List<RouteInfo>();
                
            var routes = await GetRoutingTable();
            return routes.Where(r => r.Gateway.Contains(gateway));
        }
        
        /// <summary>
        /// Gets the default route (0.0.0.0/0)
        /// </summary>
        /// <returns>The default route or null if not found</returns>
        public async Task<RouteInfo?> GetDefaultRoute()
        {
            var routes = await GetRoutingTable();
            return routes.FirstOrDefault(r => r.Destination == "0.0.0.0" || r.Destination == "default");
        }
        
        /// <summary>
        /// Executes the route command and returns its output
        /// </summary>
        private async Task<string> ExecuteRouteCommand()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "route",
                        Arguments = "-n",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                
                return !string.IsNullOrEmpty(output) ? output : string.Empty;
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }
        
        /// <summary>
        /// Parses the output of the route command into structured data
        /// </summary>
        private IEnumerable<RouteInfo> ParseRouteOutput(string routeOutput)
        {
            var routes = new List<RouteInfo>();
            
            if (string.IsNullOrWhiteSpace(routeOutput))
                return routes;
                
            var lines = routeOutput.Split('\n');
            bool tableStarted = false;
            string[]? headers = null;
            
            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                
                // Skip empty lines
                if (string.IsNullOrWhiteSpace(trimmedLine))
                    continue;
                    
                // Detect header line
                if (trimmedLine.Contains("Destination") && trimmedLine.Contains("Gateway") && trimmedLine.Contains("Genmask"))
                {
                    tableStarted = true;
                    headers = Regex.Split(trimmedLine, @"\s+").Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
                    continue;
                }
                
                // Skip lines until we find the header
                if (!tableStarted)
                    continue;
                    
                // Skip additional header lines
                if (trimmedLine.Contains("---"))
                    continue;
                    
                // Parse data rows
                var fields = Regex.Split(trimmedLine, @"\s+").Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
                
                if (fields.Length >= 8)
                {
                    routes.Add(new RouteInfo
                    {
                        Destination = fields[0],
                        Gateway = fields[1],
                        Netmask = fields[2],
                        Flags = fields[3],
                        Metric = TryParseInt(fields[4]),
                        Ref = TryParseInt(fields[5]),
                        Use = TryParseInt(fields[6]),
                        Interface = fields[7]
                    });
                }
            }
            
            return routes;
        }
        
        private int TryParseInt(string value)
        {
            return int.TryParse(value, out int result) ? result : 0;
        }
    }
    
    /// <summary>
    /// Contains information about a routing table entry
    /// </summary>
    public class RouteInfo
    {
        /// <summary>
        /// Destination network
        /// </summary>
        public string Destination { get; set; } = string.Empty;
        
        /// <summary>
        /// Gateway for this route
        /// </summary>
        public string Gateway { get; set; } = string.Empty;
        
        /// <summary>
        /// Subnet mask for the destination
        /// </summary>
        public string Netmask { get; set; } = string.Empty;
        
        /// <summary>
        /// Flags for the route (U=up, G=gateway, H=host, etc.)
        /// </summary>
        public string Flags { get; set; } = string.Empty;
        
        /// <summary>
        /// Metric/cost of the route
        /// </summary>
        public int Metric { get; set; }
        
        /// <summary>
        /// Reference count
        /// </summary>
        public int Ref { get; set; }
        
        /// <summary>
        /// Use count
        /// </summary>
        public int Use { get; set; }
        
        /// <summary>
        /// Interface name the route uses
        /// </summary>
        public string Interface { get; set; } = string.Empty;
        
        /// <summary>
        /// Whether this is a default route
        /// </summary>
        public bool IsDefaultRoute => Destination == "0.0.0.0" || Destination == "default";
        
        /// <summary>
        /// Whether this route uses a gateway
        /// </summary>
        public bool UsesGateway => Gateway != "0.0.0.0" && Gateway != "*";
        
        /// <summary>
        /// Gets the CIDR notation for this route
        /// </summary>
        public string CidrNotation
        {
            get
            {
                try
                {
                    if (IsDefaultRoute)
                        return "0.0.0.0/0";
                        
                    if (IPAddress.TryParse(Netmask, out var netmaskAddress))
                    {
                        var maskBytes = netmaskAddress.GetAddressBytes();
                        var bitCount = 0;
                        
                        foreach (var b in maskBytes)
                        {
                            bitCount += CountBitsInByte(b);
                        }
                        
                        return $"{Destination}/{bitCount}";
                    }
                    
                    return $"{Destination}/{Netmask}";
                }
                catch
                {
                    return $"{Destination}/{Netmask}";
                }
            }
        }
        
        private int CountBitsInByte(byte b)
        {
            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & (1 << (7 - i))) != 0)
                    count++;
            }
            return count;
        }
    }
}
