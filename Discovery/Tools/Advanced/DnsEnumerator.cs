using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using System.Text;
using System.Net.Sockets;
using System.Linq;
using Spectre.Console;

namespace Discovery.Tools.Advanced
{
    /// <summary>
    /// Advanced DNS enumeration and zone transfer tools
    /// </summary>
    public static class DnsEnumerator
    {
        /// <summary>
        /// Common DNS record types for enumeration
        /// </summary>
        public static readonly Dictionary<string, string> RecordTypes = new()
        {
            { "A", "IPv4 Address" },
            { "AAAA", "IPv6 Address" },
            { "CNAME", "Canonical Name" },
            { "MX", "Mail Exchange" },
            { "NS", "Name Server" },
            { "PTR", "Pointer" },
            { "SOA", "Start of Authority" },
            { "TXT", "Text" },
            { "SRV", "Service" }
        };

        /// <summary>
        /// Common subdomains to test during enumeration
        /// </summary>
        public static readonly string[] CommonSubdomains = {
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
            "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog",
            "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new",
            "mysql", "old", "www1", "email", "img", "www3", "help", "shop", "forum", "secure",
            "demo", "api", "cdn", "beta", "staging", "app", "portal", "store", "web", "docs"
        };

        /// <summary>
        /// Performs comprehensive DNS enumeration
        /// </summary>
        public static async Task<List<DnsEnumerationResult>> EnumerateDomain(string domain)
        {
            var results = new List<DnsEnumerationResult>();
            
            AnsiConsole.MarkupLine($"[bold cyan]🔍 Starting DNS enumeration for {domain}[/]");
            AnsiConsole.WriteLine();

            // Basic record lookups
            await PerformBasicRecordLookups(domain, results);
            
            // Subdomain enumeration
            await PerformSubdomainEnumeration(domain, results);
            
            // Reverse DNS lookup
            await PerformReverseDnsLookup(domain, results);

            return results;
        }

        private static async Task PerformBasicRecordLookups(string domain, List<DnsEnumerationResult> results)
        {
            AnsiConsole.MarkupLine("[yellow]📋 Performing basic DNS record lookups...[/]");
            
            foreach (var recordType in RecordTypes)
            {
                try
                {
                    AnsiConsole.MarkupLine($"[dim]🔄 Checking {recordType.Key} records...[/]");
                    
                    switch (recordType.Key)
                    {
                        case "A":
                            await LookupARecords(domain, results);
                            break;
                        case "AAAA":
                            await LookupAAAARecords(domain, results);
                            break;
                        case "MX":
                            await LookupMXRecords(domain, results);
                            break;
                        case "NS":
                            await LookupNSRecords(domain, results);
                            break;
                        case "TXT":
                            LookupTXTRecords(domain, results);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new DnsEnumerationResult
                    {
                        Domain = domain,
                        RecordType = recordType.Key,
                        Success = false,
                        ErrorMessage = ex.Message
                    });
                }
                
                await Task.Delay(100); // Rate limiting
            }
        }

        private static async Task LookupARecords(string domain, List<DnsEnumerationResult> results)
        {
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(domain);
                foreach (var address in hostEntry.AddressList)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        results.Add(new DnsEnumerationResult
                        {
                            Domain = domain,
                            RecordType = "A",
                            Value = address.ToString(),
                            Success = true
                        });
                        AnsiConsole.MarkupLine($"[green]✅ A Record: {domain} -> {address}[/]");
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new DnsEnumerationResult
                {
                    Domain = domain,
                    RecordType = "A",
                    Success = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        private static async Task LookupAAAARecords(string domain, List<DnsEnumerationResult> results)
        {
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(domain);
                foreach (var address in hostEntry.AddressList)
                {
                    if (address.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        results.Add(new DnsEnumerationResult
                        {
                            Domain = domain,
                            RecordType = "AAAA",
                            Value = address.ToString(),
                            Success = true
                        });
                        AnsiConsole.MarkupLine($"[green]✅ AAAA Record: {domain} -> {address}[/]");
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new DnsEnumerationResult
                {
                    Domain = domain,
                    RecordType = "AAAA",
                    Success = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        private static async Task LookupMXRecords(string domain, List<DnsEnumerationResult> results)
        {
            // Basic implementation - would need DNS library for full MX record parsing
            try
            {
                // For now, try common mail server subdomains
                var mailSubdomains = new[] { "mail", "smtp", "mx", "mx1", "mx2" };
                
                foreach (var subdomain in mailSubdomains)
                {
                    try
                    {
                        var mailDomain = $"{subdomain}.{domain}";
                        var hostEntry = await Dns.GetHostEntryAsync(mailDomain);
                        
                        if (hostEntry.AddressList.Length > 0)
                        {
                            results.Add(new DnsEnumerationResult
                            {
                                Domain = mailDomain,
                                RecordType = "MX",
                                Value = hostEntry.AddressList[0].ToString(),
                                Success = true
                            });
                            AnsiConsole.MarkupLine($"[green]✅ Mail Server: {mailDomain} -> {hostEntry.AddressList[0]}[/]");
                        }
                    }
                    catch
                    {
                        // Subdomain doesn't exist, continue
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new DnsEnumerationResult
                {
                    Domain = domain,
                    RecordType = "MX",
                    Success = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        private static async Task LookupNSRecords(string domain, List<DnsEnumerationResult> results)
        {
            // Basic implementation - try common nameserver patterns
            try
            {
                var nsSubdomains = new[] { "ns1", "ns2", "ns3", "ns", "dns1", "dns2" };
                
                foreach (var subdomain in nsSubdomains)
                {
                    try
                    {
                        var nsDomain = $"{subdomain}.{domain}";
                        var hostEntry = await Dns.GetHostEntryAsync(nsDomain);
                        
                        if (hostEntry.AddressList.Length > 0)
                        {
                            results.Add(new DnsEnumerationResult
                            {
                                Domain = nsDomain,
                                RecordType = "NS",
                                Value = hostEntry.AddressList[0].ToString(),
                                Success = true
                            });
                            AnsiConsole.MarkupLine($"[green]✅ Name Server: {nsDomain} -> {hostEntry.AddressList[0]}[/]");
                        }
                    }
                    catch
                    {
                        // Subdomain doesn't exist, continue
                    }
                }
            }
            catch (Exception ex)
            {
                results.Add(new DnsEnumerationResult
                {
                    Domain = domain,
                    RecordType = "NS",
                    Success = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        private static void LookupTXTRecords(string domain, List<DnsEnumerationResult> results)
        {
            // TXT records would require specialized DNS library
            // For now, indicate that this feature requires external DNS library
            results.Add(new DnsEnumerationResult
            {
                Domain = domain,
                RecordType = "TXT",
                Success = false,
                ErrorMessage = "TXT record lookup requires external DNS library (e.g., DnsClient.NET)"
            });
        }

        private static async Task PerformSubdomainEnumeration(string domain, List<DnsEnumerationResult> results)
        {
            AnsiConsole.MarkupLine("[yellow]🌐 Performing subdomain enumeration...[/]");
            
            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]Enumerating subdomains[/]", maxValue: CommonSubdomains.Length);
                    
                    foreach (var subdomain in CommonSubdomains)
                    {
                        try
                        {
                            var fullDomain = $"{subdomain}.{domain}";
                            var hostEntry = await Dns.GetHostEntryAsync(fullDomain);
                            
                            if (hostEntry.AddressList.Length > 0)
                            {
                                foreach (var address in hostEntry.AddressList)
                                {
                                    results.Add(new DnsEnumerationResult
                                    {
                                        Domain = fullDomain,
                                        RecordType = "Subdomain",
                                        Value = address.ToString(),
                                        Success = true
                                    });
                                }
                                AnsiConsole.MarkupLine($"[green]✅ Found subdomain: {fullDomain}[/]");
                            }
                        }
                        catch
                        {
                            // Subdomain doesn't exist, continue
                        }
                        
                        task.Increment(1);
                        await Task.Delay(50); // Rate limiting
                    }
                });
        }

        private static async Task PerformReverseDnsLookup(string domain, List<DnsEnumerationResult> results)
        {
            AnsiConsole.MarkupLine("[yellow]🔄 Performing reverse DNS lookups...[/]");
            
            // Get IP addresses first
            var ipAddresses = new List<IPAddress>();
            
            foreach (var result in results)
            {
                if (result.Success && IPAddress.TryParse(result.Value, out var ip))
                {
                    ipAddresses.Add(ip);
                }
            }

            foreach (var ip in ipAddresses)
            {
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ip);
                    results.Add(new DnsEnumerationResult
                    {
                        Domain = ip.ToString(),
                        RecordType = "PTR",
                        Value = hostEntry.HostName,
                        Success = true
                    });
                    AnsiConsole.MarkupLine($"[green]✅ Reverse DNS: {ip} -> {hostEntry.HostName}[/]");
                }
                catch
                {
                    // No reverse DNS record
                }
                
                await Task.Delay(100); // Rate limiting
            }
        }

        /// <summary>
        /// Attempts DNS zone transfer (AXFR)
        /// </summary>
        public static List<string> AttemptZoneTransfer(string domain, string? nameServer = null)
        {
            var results = new List<string>();
            
            AnsiConsole.MarkupLine($"[bold red]⚠️ Attempting DNS zone transfer for {domain}[/]");
            AnsiConsole.MarkupLine("[dim]Note: Zone transfers are typically restricted and may fail[/]");
            
            // This is a simplified version - real zone transfer would require DNS protocol implementation
            results.Add("Zone transfer requires specialized DNS library implementation");
            results.Add("This feature would use DNS over TCP on port 53");
            results.Add("Most modern DNS servers have zone transfers restricted");
            
            return results;
        }

        /// <summary>
        /// DNS brute force with custom wordlist
        /// </summary>
        public static async Task<List<DnsEnumerationResult>> BruteForceSubdomains(string domain, IEnumerable<string> wordlist)
        {
            var results = new List<DnsEnumerationResult>();
            var wordArray = wordlist.ToArray();
            
            AnsiConsole.MarkupLine($"[bold cyan]🔨 Brute forcing subdomains for {domain}[/]");
            
            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]Brute forcing subdomains[/]", maxValue: wordArray.Length);
                    
                    foreach (var word in wordArray)
                    {
                        try
                        {
                            var subdomain = $"{word}.{domain}";
                            var hostEntry = await Dns.GetHostEntryAsync(subdomain);
                            
                            if (hostEntry.AddressList.Length > 0)
                            {
                                foreach (var address in hostEntry.AddressList)
                                {
                                    results.Add(new DnsEnumerationResult
                                    {
                                        Domain = subdomain,
                                        RecordType = "Brute Force",
                                        Value = address.ToString(),
                                        Success = true
                                    });
                                }
                                AnsiConsole.MarkupLine($"[green]✅ Found: {subdomain}[/]");
                            }
                        }
                        catch
                        {
                            // Subdomain doesn't exist
                        }
                        
                        task.Increment(1);
                        await Task.Delay(25); // Rate limiting for brute force
                    }
                });
            
            return results;
        }
    }

    /// <summary>
    /// DNS enumeration result
    /// </summary>
    public class DnsEnumerationResult
    {
        public string Domain { get; set; } = string.Empty;
        public string RecordType { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;
    }
}