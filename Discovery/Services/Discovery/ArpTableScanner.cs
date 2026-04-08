using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;

namespace Discovery.Services.Discovery
{
    /// <summary>
    /// Implements ARP table scanning functionality
    /// </summary>
    public class ArpTableScanner
    {
        /// <summary>
        /// Gets the current ARP table from the system
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>A dictionary mapping IP addresses to MAC addresses</returns>
        public async Task<Dictionary<string, string>> GetArpTableAsync(CancellationToken cancellationToken = default)
        {
            var arpTable = new Dictionary<string, string>();
            var allTasks = new List<Task>();
            var syncLock = new object();
            
            try
            {
                // Method 1: Try 'arp -a' command (Windows & older Linux)
                allTasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var process = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = "arp",
                                Arguments = "-a",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            }
                        };
                        
                        process.Start();
                        var output = await process.StandardOutput.ReadToEndAsync();
                        await process.WaitForExitAsync(cancellationToken);
                        
                        if (!string.IsNullOrEmpty(output))
                        {
                            ParseArpOutput(output, arpTable, syncLock);
                        }
                    }
                    catch
                    {
                        // Ignore errors and try next method
                    }
                }, cancellationToken));

                // Method 2: Try 'ip neigh' command (modern Linux)
                allTasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var process = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = "ip",
                                Arguments = "neigh show",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            }
                        };
                        
                        process.Start();
                        var output = await process.StandardOutput.ReadToEndAsync();
                        await process.WaitForExitAsync(cancellationToken);
                        
                        if (!string.IsNullOrEmpty(output))
                        {
                            ParseIpNeighOutput(output, arpTable, syncLock);
                        }
                    }
                    catch
                    {
                        // Ignore errors and try next method
                    }
                }, cancellationToken));

                // Method 3: Try reading from /proc/net/arp on Linux
                allTasks.Add(Task.Run(() =>
                {
                    try
                    {
                        if (System.IO.File.Exists("/proc/net/arp"))
                        {
                            var arpFileContent = System.IO.File.ReadAllText("/proc/net/arp");
                            ParseArpFileOutput(arpFileContent, arpTable, syncLock);
                        }
                    }
                    catch
                    {
                        // Ignore errors
                    }
                    return Task.CompletedTask;
                }));

                await Task.WhenAll(allTasks);
            }
            catch (OperationCanceledException)
            {
                // Operation was cancelled
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error retrieving ARP table: {ex.Message}[/]");
            }
            
            return arpTable;
        }
        
        /// <summary>
        /// Performs an ARP scan on the network
        /// </summary>
        /// <param name="cidrNotation">The CIDR notation (e.g. 192.168.1.0/24)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>A dictionary mapping IP addresses to MAC addresses</returns>
        public async Task<Dictionary<string, string>> ScanArpAsync(string cidrNotation, CancellationToken cancellationToken = default)
        {
            // First ping the network to populate the ARP cache
            var pingSweeper = new PingSweeper();
            await pingSweeper.PingSweepCidrAsync(cidrNotation, cancellationToken);
            
            // Now get the ARP table which should contain the newly discovered hosts
            return await GetArpTableAsync(cancellationToken);
        }
        
        /// <summary>
        /// Gets the manufacturer for a MAC address using OUI database
        /// </summary>
        /// <param name="macAddress">The MAC address</param>
        /// <returns>The manufacturer name if found, otherwise "Unknown"</returns>
        public string GetManufacturerFromMac(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress))
                return "Unknown";
                
            // Normalize MAC address format
            macAddress = macAddress.Replace(":", "").Replace("-", "").Replace(".", "").ToUpper();
            
            if (macAddress.Length < 6)
                return "Unknown";
                
            // Extract OUI (first 6 characters)
            string oui = macAddress.Substring(0, 6);
            
            // Simple built-in database of common OUIs
            // In a real implementation, this would be a more comprehensive database
            return oui switch
            {
                "000C29" => "VMware, Inc.",
                "001122" => "Cisco Systems, Inc.",
                "0080C8" => "D-Link Systems, Inc.",
                "001D0F" => "TP-Link Technologies Co., Ltd.",
                "001018" => "Broadcom Corporation",
                "B8D7AF" => "Murata Manufacturing Co., Ltd.",
                "7CB0C2" => "Intel Corporate",
                "0C5422" => "Dell Inc.",
                "B8AC6F" => "Dell Inc.",
                "F0F002" => "Hewlett Packard Enterprise",
                "001A4B" => "Hewlett Packard Enterprise",
                "001871" => "Hewlett Packard Enterprise",
                "FC15B4" => "Hewlett Packard Enterprise",
                "3CD92B" => "Hewlett Packard Enterprise",
                "984BE1" => "Hewlett Packard Enterprise",
                "D8D385" => "Hewlett Packard Enterprise",
                "DCFB02" => "Apple, Inc.",
                "58B035" => "Apple, Inc.",
                "4C57CA" => "Apple, Inc.",
                "88E9FE" => "Apple, Inc.",
                "8863DF" => "Apple, Inc.",
                "B8F6B1" => "Apple, Inc.",
                "FCFC48" => "Apple, Inc.",
                "CC4EEC" => "Huawei Technologies Co., Ltd.",
                "AC8742" => "Huawei Technologies Co., Ltd.",
                "0823B2" => "Samsung Electronics Co., Ltd.",
                "14F42A" => "Samsung Electronics Co., Ltd.",
                "5001BB" => "Samsung Electronics Co., Ltd.",
                "9893CC" => "LG Electronics Inc.",
                "5C497D" => "LG Electronics Inc.",
                "647002" => "TP-Link Technologies Co., Ltd.",
                "D07714" => "Motorola Mobility LLC, a Lenovo Company",
                "C0BDD1" => "Samsung Electro Mechanics Co., Ltd.",
                "F4BD9E" => "Cisco Systems, Inc.",
                "00AA00" => "Intel Corporation",
                _ => "Unknown"
            };
        }
        
        #region Helper Methods
        
        /// <summary>
        /// Parses output from 'arp -a' command
        /// </summary>
        private void ParseArpOutput(string output, Dictionary<string, string> arpTable, object syncLock)
        {
            // Regex to extract IP and MAC from Windows arp -a output (Windows format)
            var windowsRegex = new Regex(@"(\d+\.\d+\.\d+\.\d+)\s+([\w\-]+)\s+([\w\-:]+)", RegexOptions.Multiline);
            var matches = windowsRegex.Matches(output);
            
            if (matches.Count > 0)
            {
                lock (syncLock)
                {
                    foreach (Match match in matches)
                    {
                        if (match.Groups.Count >= 4)
                        {
                            var ip = match.Groups[1].Value;
                            var mac = match.Groups[3].Value;
                            
                            if (!string.IsNullOrWhiteSpace(mac) && mac != "ff-ff-ff-ff-ff-ff" && !arpTable.ContainsKey(ip))
                            {
                                arpTable[ip] = mac;
                            }
                        }
                    }
                }
                return;
            }
            
            // Regex to extract IP and MAC from Unix arp -a output (Unix format)
            var unixRegex = new Regex(@"(\d+\.\d+\.\d+\.\d+)\s+ether\s+([\w:]+)", RegexOptions.Multiline);
            matches = unixRegex.Matches(output);
            
            if (matches.Count > 0)
            {
                lock (syncLock)
                {
                    foreach (Match match in matches)
                    {
                        if (match.Groups.Count >= 3)
                        {
                            var ip = match.Groups[1].Value;
                            var mac = match.Groups[2].Value;
                            
                            if (!string.IsNullOrWhiteSpace(mac) && !arpTable.ContainsKey(ip))
                            {
                                arpTable[ip] = mac;
                            }
                        }
                    }
                }
            }
        }
        
        /// <summary>
        /// Parses output from 'ip neigh' command
        /// </summary>
        private void ParseIpNeighOutput(string output, Dictionary<string, string> arpTable, object syncLock)
        {
            // Each line format: 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            var regex = new Regex(@"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([\w:]+)", RegexOptions.Multiline);
            var matches = regex.Matches(output);
            
            lock (syncLock)
            {
                foreach (Match match in matches)
                {
                    if (match.Groups.Count >= 3)
                    {
                        var ip = match.Groups[1].Value;
                        var mac = match.Groups[2].Value;
                        
                        if (!string.IsNullOrWhiteSpace(mac) && !arpTable.ContainsKey(ip))
                        {
                            arpTable[ip] = mac;
                        }
                    }
                }
            }
        }
        
        /// <summary>
        /// Parses output from /proc/net/arp file
        /// </summary>
        private void ParseArpFileOutput(string output, Dictionary<string, string> arpTable, object syncLock)
        {
            // Skip header line
            var lines = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            
            if (lines.Length <= 1)
                return;
                
            lock (syncLock)
            {
                for (int i = 1; i < lines.Length; i++)
                {
                    var fields = lines[i].Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    
                    if (fields.Length >= 4)
                    {
                        var ip = fields[0];
                        var mac = fields[3];
                        
                        if (!string.IsNullOrWhiteSpace(mac) && mac != "00:00:00:00:00:00" && !arpTable.ContainsKey(ip))
                        {
                            arpTable[ip] = mac;
                        }
                    }
                }
            }
        }
        
        #endregion
    }
}
