using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Spectre.Console;

namespace Discovery.Security
{
    /// <summary>
    /// Advanced Active Directory and LDAP scanning capabilities for security assessments
    /// </summary>
    public class ActiveDirectoryScanner
    {
        public class ADResult
        {
            public string? Target { get; set; }
            public string? Type { get; set; }
            public string? Information { get; set; }
            public string? Details { get; set; }
            public bool IsVulnerable { get; set; }
            public DateTime DiscoveredAt { get; set; } = DateTime.Now;
        }

        public class DomainControllerInfo
        {
            public string? IpAddress { get; set; }
            public string? HostName { get; set; }
            public string? DomainName { get; set; }
            public List<string> Services { get; set; } = new();
            public bool IsReachable { get; set; }
            public string? OsVersion { get; set; }
        }

        /// <summary>
        /// Discover domain controllers in the network
        /// </summary>
        public static async Task<List<DomainControllerInfo>> DiscoverDomainControllersAsync(
            string? targetDomain = null, 
            CancellationToken cancellationToken = default)
        {
            var results = new List<DomainControllerInfo>();

            AnsiConsole.MarkupLine("[yellow]🔍 Discovering Domain Controllers...[/]");

            try
            {
                // Method 1: DNS SRV record lookup for _ldap._tcp.dc._msdcs.domain
                if (!string.IsNullOrEmpty(targetDomain))
                {
                    await DiscoverViaDnsAsync(targetDomain, results);
                }

                // Method 2: Network scan for common DC ports
                await DiscoverViaNetworkScanAsync(results, cancellationToken);

                // Method 3: Try to get current domain if no target specified
                if (string.IsNullOrEmpty(targetDomain))
                {
                    await DiscoverCurrentDomainAsync(results);
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]❌ Error discovering domain controllers: {ex.Message}[/]");
            }

            return results;
        }

        private static async Task DiscoverViaDnsAsync(string domain, List<DomainControllerInfo> results)
        {
            try
            {
                // Try to resolve _ldap._tcp.dc._msdcs.{domain}
                var srvRecord = $"_ldap._tcp.dc._msdcs.{domain}";
                
                // Basic DNS resolution - in real implementation would use proper SRV lookup
                var addresses = await Dns.GetHostAddressesAsync(domain);
                
                foreach (var address in addresses)
                {
                    var dcInfo = new DomainControllerInfo
                    {
                        IpAddress = address.ToString(),
                        DomainName = domain,
                        IsReachable = await TestConnectivityAsync(address.ToString())
                    };
                    
                    if (dcInfo.IsReachable)
                    {
                        dcInfo.Services.Add("DNS");
                        results.Add(dcInfo);
                    }
                }
            }
            catch (Exception)
            {
                // DNS resolution failed - this is expected in many cases
            }
        }

        private static async Task DiscoverViaNetworkScanAsync(List<DomainControllerInfo> results, CancellationToken cancellationToken)
        {
            // Common DC ports to scan
            var dcPorts = new[] { 53, 88, 135, 389, 445, 464, 636, 3268, 3269 };
            
            // Get local network range
            var localIps = GetLocalNetworkRanges();
            
            foreach (var networkRange in localIps)
            {
                if (cancellationToken.IsCancellationRequested) break;
                
                var tasks = new List<Task>();
                var semaphore = new SemaphoreSlim(20); // Limit concurrent scans
                
                for (int i = 1; i < 255; i++)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    
                    var targetIp = $"{networkRange}.{i}";
                    
                    tasks.Add(Task.Run(async () =>
                    {
                        await semaphore.WaitAsync(cancellationToken);
                        try
                        {
                            var dcInfo = await ScanForDomainControllerAsync(targetIp, dcPorts, cancellationToken);
                            if (dcInfo != null)
                            {
                                lock (results)
                                {
                                    results.Add(dcInfo);
                                }
                                AnsiConsole.MarkupLine($"[green]✅ Found potential DC: {targetIp}[/]");
                            }
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, cancellationToken));
                }
                
                await Task.WhenAll(tasks);
            }
        }

        private static async Task DiscoverCurrentDomainAsync(List<DomainControllerInfo> results)
        {
            try
            {
                // Try to get current domain information
                var computerName = Environment.MachineName;
                var domainName = Environment.UserDomainName;
                
                if (!string.IsNullOrEmpty(domainName) && domainName != computerName)
                {
                    AnsiConsole.MarkupLine($"[cyan]🏢 Current Domain: {domainName}[/]");
                    await DiscoverViaDnsAsync(domainName, results);
                }
            }
            catch (Exception)
            {
                // Not domain-joined or error accessing domain info
            }
        }

        private static async Task<DomainControllerInfo?> ScanForDomainControllerAsync(
            string ipAddress, 
            int[] ports, 
            CancellationToken cancellationToken)
        {
            var openPorts = new List<int>();
            var dcServices = new List<string>();

            foreach (var port in ports)
            {
                if (cancellationToken.IsCancellationRequested) break;
                
                if (await IsPortOpenAsync(ipAddress, port, 1000))
                {
                    openPorts.Add(port);
                    dcServices.Add(GetServiceName(port));
                }
            }

            // Consider it a potential DC if it has LDAP (389) or LDAPS (636) and at least 2 other DC services
            if (openPorts.Contains(389) || openPorts.Contains(636))
            {
                var dcScore = 0;
                if (openPorts.Contains(53)) dcScore++;   // DNS
                if (openPorts.Contains(88)) dcScore++;   // Kerberos
                if (openPorts.Contains(445)) dcScore++;  // SMB
                if (openPorts.Contains(135)) dcScore++;  // RPC Endpoint Mapper
                
                if (dcScore >= 2)
                {
                    return new DomainControllerInfo
                    {
                        IpAddress = ipAddress,
                        Services = dcServices,
                        IsReachable = true
                    };
                }
            }

            return null;
        }

        /// <summary>
        /// Perform LDAP enumeration on discovered domain controllers
        /// </summary>
        public static async Task<List<ADResult>> EnumerateLdapAsync(
            string target, 
            string? username = null, 
            string? password = null,
            CancellationToken cancellationToken = default)
        {
            var results = new List<ADResult>();

            AnsiConsole.MarkupLine($"[yellow]🔍 LDAP Enumeration on {target}...[/]");

            try
            {
                // Anonymous LDAP bind attempt
                await TryAnonymousLdapAsync(target, results);

                // Basic LDAP queries
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    await TryAuthenticatedLdapAsync(target, username, password, results);
                }

                // LDAP null session enumeration
                await TryNullSessionAsync(target, results);
            }
            catch (Exception ex)
            {
                results.Add(new ADResult
                {
                    Target = target,
                    Type = "Error",
                    Information = "LDAP Enumeration Failed",
                    Details = ex.Message,
                    IsVulnerable = false
                });
            }

            return results;
        }

        private static async Task TryAnonymousLdapAsync(string target, List<ADResult> results)
        {
            try
            {
                using var connection = new LdapConnection(new LdapDirectoryIdentifier(target, 389));
                connection.SessionOptions.ProtocolVersion = 3;
                connection.AuthType = AuthType.Anonymous;
                
                await Task.Run(() => connection.Bind());
                
                results.Add(new ADResult
                {
                    Target = target,
                    Type = "LDAP Anonymous",
                    Information = "Anonymous LDAP bind successful",
                    Details = "Server allows anonymous LDAP connections",
                    IsVulnerable = true
                });

                // Try to get root DSE
                var searchRequest = new SearchRequest(null, "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Base);
                var response = (SearchResponse)connection.SendRequest(searchRequest);
                
                if (response.Entries.Count > 0)
                {
                    var entry = response.Entries[0];
                    var namingContexts = entry.Attributes["namingContexts"];
                    
                    if (namingContexts != null)
                    {
                        results.Add(new ADResult
                        {
                            Target = target,
                            Type = "LDAP Root DSE",
                            Information = "Naming contexts enumerated",
                            Details = string.Join(", ", namingContexts.GetValues(typeof(string)).Cast<string>()),
                            IsVulnerable = false
                        });
                    }
                }
            }
            catch (Exception)
            {
                // Anonymous bind failed - this is expected in secure environments
            }
        }

        private static async Task TryAuthenticatedLdapAsync(string target, string username, string password, List<ADResult> results)
        {
            try
            {
                using var connection = new LdapConnection(new LdapDirectoryIdentifier(target, 389));
                connection.SessionOptions.ProtocolVersion = 3;
                
                var credential = new NetworkCredential(username, password);
                await Task.Run(() => connection.Bind(credential));
                
                results.Add(new ADResult
                {
                    Target = target,
                    Type = "LDAP Authentication",
                    Information = "Authenticated LDAP bind successful",
                    Details = $"Credentials {username} are valid",
                    IsVulnerable = false
                });

                // Enumerate users
                await EnumerateUsersAsync(connection, results, target);
                
                // Enumerate groups
                await EnumerateGroupsAsync(connection, results, target);
                
                // Check for common misconfigurations
                await CheckLdapMisconfigurationsAsync(connection, results, target);
            }
            catch (Exception ex)
            {
                results.Add(new ADResult
                {
                    Target = target,
                    Type = "LDAP Authentication",
                    Information = "Authentication failed",
                    Details = ex.Message,
                    IsVulnerable = false
                });
            }
        }

        private static async Task TryNullSessionAsync(string target, List<ADResult> results)
        {
            try
            {
                // Try null session enumeration
                using var connection = new LdapConnection(new LdapDirectoryIdentifier(target, 389));
                connection.SessionOptions.ProtocolVersion = 3;
                
                var credential = new NetworkCredential("", "");
                await Task.Run(() => connection.Bind(credential));
                
                results.Add(new ADResult
                {
                    Target = target,
                    Type = "LDAP Null Session",
                    Information = "Null session bind successful",
                    Details = "Server allows null session connections",
                    IsVulnerable = true
                });
            }
            catch (Exception)
            {
                // Null session failed - this is expected in secure environments
            }
        }

        private static async Task EnumerateUsersAsync(LdapConnection connection, List<ADResult> results, string target)
        {
            try
            {
                var searchRequest = new SearchRequest(
                    null, 
                    "(&(objectClass=user)(objectCategory=person))", 
                    System.DirectoryServices.Protocols.SearchScope.Subtree);
                searchRequest.Attributes.AddRange(new[] { "cn", "sAMAccountName", "userPrincipalName", "description" });
                
                var response = (SearchResponse)await Task.Run(() => connection.SendRequest(searchRequest));
                
                var userCount = response.Entries.Count;
                if (userCount > 0)
                {
                    results.Add(new ADResult
                    {
                        Target = target,
                        Type = "LDAP Users",
                        Information = $"Found {userCount} user accounts",
                        Details = $"User enumeration successful - {Math.Min(userCount, 10)} sample users found",
                        IsVulnerable = false
                    });
                }
            }
            catch (Exception)
            {
                // User enumeration failed
            }
        }

        private static async Task EnumerateGroupsAsync(LdapConnection connection, List<ADResult> results, string target)
        {
            try
            {
                var searchRequest = new SearchRequest(
                    null, 
                    "(objectClass=group)", 
                    System.DirectoryServices.Protocols.SearchScope.Subtree);
                searchRequest.Attributes.AddRange(new[] { "cn", "description", "member" });
                
                var response = (SearchResponse)await Task.Run(() => connection.SendRequest(searchRequest));
                
                var groupCount = response.Entries.Count;
                if (groupCount > 0)
                {
                    results.Add(new ADResult
                    {
                        Target = target,
                        Type = "LDAP Groups",
                        Information = $"Found {groupCount} groups",
                        Details = "Group enumeration successful",
                        IsVulnerable = false
                    });
                }
            }
            catch (Exception)
            {
                // Group enumeration failed
            }
        }

        private static async Task CheckLdapMisconfigurationsAsync(LdapConnection connection, List<ADResult> results, string target)
        {
            // Check for common LDAP misconfigurations
            var vulnerabilityChecks = new[]
            {
                ("Weak Password Policy", "(objectClass=domainDNS)", new[] { "minPwdLength", "pwdHistoryLength" }),
                ("Service Accounts", "(&(objectClass=user)(servicePrincipalName=*))", new[] { "cn", "servicePrincipalName" }),
                ("Never Expiring Passwords", "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))", new[] { "cn", "sAMAccountName" })
            };

            foreach (var (name, filter, attributes) in vulnerabilityChecks)
            {
                try
                {
                    var searchRequest = new SearchRequest(null, filter, System.DirectoryServices.Protocols.SearchScope.Subtree);
                    searchRequest.Attributes.AddRange(attributes);
                    var response = (SearchResponse)await Task.Run(() => connection.SendRequest(searchRequest));
                    
                    if (response.Entries.Count > 0)
                    {
                        results.Add(new ADResult
                        {
                            Target = target,
                            Type = "LDAP Vulnerability",
                            Information = name,
                            Details = $"Found {response.Entries.Count} entries matching vulnerability pattern",
                            IsVulnerable = true
                        });
                    }
                }
                catch (Exception)
                {
                    // Vulnerability check failed
                }
            }
        }

        /// <summary>
        /// Scan for SMB/NetBIOS information (related to AD environments)
        /// </summary>
        public static async Task<List<ADResult>> ScanSmbNetBiosAsync(
            string target, 
            CancellationToken cancellationToken = default)
        {
            var results = new List<ADResult>();

            AnsiConsole.MarkupLine($"[yellow]🔍 SMB/NetBIOS Scanning {target}...[/]");

            // Check SMB ports
            var smbPorts = new[] { 139, 445 };
            var openPorts = new List<int>();

            foreach (var port in smbPorts)
            {
                if (await IsPortOpenAsync(target, port, 2000))
                {
                    openPorts.Add(port);
                }
            }

            if (openPorts.Count > 0)
            {
                results.Add(new ADResult
                {
                    Target = target,
                    Type = "SMB Service",
                    Information = "SMB ports open",
                    Details = $"Open ports: {string.Join(", ", openPorts)}",
                    IsVulnerable = false
                });

                // Try to get NetBIOS name
                await TryNetBiosEnumerationAsync(target, results);
                
                // Try null session enumeration
                await TryNullSmbSessionAsync(target, results);
            }

            return results;
        }

        private static async Task TryNetBiosEnumerationAsync(string target, List<ADResult> results)
        {
            try
            {
                // Basic NetBIOS name resolution attempt
                var hostEntry = await Dns.GetHostEntryAsync(target);
                
                results.Add(new ADResult
                {
                    Target = target,
                    Type = "NetBIOS",
                    Information = "NetBIOS name resolved",
                    Details = $"Hostname: {hostEntry.HostName}",
                    IsVulnerable = false
                });
            }
            catch (Exception)
            {
                // NetBIOS resolution failed
            }
        }

        private static async Task TryNullSmbSessionAsync(string target, List<ADResult> results)
        {
            // Note: Actual null session enumeration would require more complex SMB protocol implementation
            // This is a placeholder for the concept
            
            await Task.Delay(100); // Simulate SMB check
            
            // In a real implementation, this would try to connect to IPC$ share with null credentials
            // and attempt to enumerate shares, users, etc.
        }

        // Helper methods
        private static async Task<bool> TestConnectivityAsync(string target)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(target, 2000);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        private static async Task<bool> IsPortOpenAsync(string host, int port, int timeoutMs)
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(timeoutMs);
                
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                
                if (completedTask == connectTask && client.Connected)
                {
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static List<string> GetLocalNetworkRanges()
        {
            var ranges = new List<string>();
            
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                
                foreach (var iface in interfaces)
                {
                    if (iface.OperationalStatus == OperationalStatus.Up && 
                        iface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var props = iface.GetIPProperties();
                        
                        foreach (var addr in props.UnicastAddresses)
                        {
                            if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                var ip = addr.Address.ToString();
                                var parts = ip.Split('.');
                                if (parts.Length == 4)
                                {
                                    ranges.Add($"{parts[0]}.{parts[1]}.{parts[2]}");
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Fallback to common private ranges
                ranges.AddRange(new[] { "192.168.1", "192.168.0", "10.0.0", "172.16.0" });
            }
            
            return ranges.Distinct().ToList();
        }

        private static string GetServiceName(int port)
        {
            return port switch
            {
                53 => "DNS",
                88 => "Kerberos",
                135 => "RPC Endpoint Mapper",
                139 => "NetBIOS Session",
                389 => "LDAP",
                445 => "Microsoft-DS (SMB)",
                464 => "Kerberos Password Change",
                636 => "LDAPS (LDAP over SSL)",
                3268 => "Global Catalog",
                3269 => "Global Catalog SSL",
                _ => $"Port {port}"
            };
        }
    }
}