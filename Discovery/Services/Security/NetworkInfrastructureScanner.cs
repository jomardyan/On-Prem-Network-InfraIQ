using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Spectre.Console;

namespace Discovery.Services.Security
{
    /// <summary>
    /// Advanced network infrastructure vulnerability scanner for routers, switches, IoT devices, and network appliances
    /// </summary>
    public class NetworkInfrastructureScanner
    {
        private readonly int _timeout;

        // Network infrastructure device signatures
        private static readonly Dictionary<string, InfrastructureSignature> DeviceSignatures = new()
        {
            ["Cisco Router"] = new InfrastructureSignature
            {
                Ports = new[] { 22, 23, 80, 443, 161, 162, 514 },
                BannerPatterns = new[] { "Cisco", "IOS", "CISCO" },
                HttpTitlePatterns = new[] { "Cisco", "IOS HTTP", "Cisco Systems" },
                VulnerabilityLevel = VulnerabilitySeverity.High
            },
            ["Mikrotik Router"] = new InfrastructureSignature
            {
                Ports = new[] { 22, 23, 80, 443, 8291, 8728 },
                BannerPatterns = new[] { "MikroTik", "RouterOS" },
                HttpTitlePatterns = new[] { "RouterOS", "MikroTik" },
                VulnerabilityLevel = VulnerabilitySeverity.High
            },
            ["Ubiquiti Device"] = new InfrastructureSignature
            {
                Ports = new[] { 22, 80, 443, 8080, 8443 },
                BannerPatterns = new[] { "Ubiquiti", "EdgeRouter", "UniFi" },
                HttpTitlePatterns = new[] { "UniFi", "EdgeRouter", "Ubiquiti" },
                VulnerabilityLevel = VulnerabilitySeverity.Medium
            },
            ["Netgear Device"] = new InfrastructureSignature
            {
                Ports = new[] { 80, 443, 8080 },
                BannerPatterns = new[] { "NETGEAR" },
                HttpTitlePatterns = new[] { "NETGEAR", "ReadyNAS", "ProSAFE" },
                VulnerabilityLevel = VulnerabilitySeverity.Medium
            },
            ["D-Link Device"] = new InfrastructureSignature
            {
                Ports = new[] { 80, 443 },
                BannerPatterns = new[] { "D-Link" },
                HttpTitlePatterns = new[] { "D-Link", "DGS-", "DIR-" },
                VulnerabilityLevel = VulnerabilitySeverity.Medium
            },
            ["TP-Link Device"] = new InfrastructureSignature
            {
                Ports = new[] { 80, 443 },
                BannerPatterns = new[] { "TP-Link", "TP-LINK" },
                HttpTitlePatterns = new[] { "TP-Link", "TL-", "Archer" },
                VulnerabilityLevel = VulnerabilitySeverity.Medium
            },
            ["SNMP Device"] = new InfrastructureSignature
            {
                Ports = new[] { 161, 162 },
                BannerPatterns = Array.Empty<string>(),
                HttpTitlePatterns = Array.Empty<string>(),
                VulnerabilityLevel = VulnerabilitySeverity.Medium
            },
            ["Industrial Controller"] = new InfrastructureSignature
            {
                Ports = new[] { 502, 1911, 2404, 20000, 44818 },
                BannerPatterns = new[] { "Modbus", "Schneider", "Siemens", "Allen-Bradley" },
                HttpTitlePatterns = new[] { "SCADA", "HMI", "PLC" },
                VulnerabilityLevel = VulnerabilitySeverity.Critical
            }
        };

        // Common IoT device ports and services
        private static readonly Dictionary<int, string> IoTServicePorts = new()
        {
            [1883] = "MQTT",
            [1884] = "MQTT over SSL",
            [8883] = "MQTT over SSL",
            [5683] = "CoAP",
            [5684] = "CoAP over DTLS",
            [1900] = "UPnP",
            [5000] = "UPnP",
            [8080] = "HTTP Alt",
            [8443] = "HTTPS Alt",
            [9000] = "Management Interface",
            [10000] = "Web Management",
            [32400] = "Plex Media Server",
            [8008] = "HTTP Alt",
            [7001] = "Cassandra/Alt HTTP",
            [9200] = "Elasticsearch",
            [27017] = "MongoDB",
            [6379] = "Redis",
            [11211] = "Memcached",
            [5432] = "PostgreSQL",
            [3306] = "MySQL",
            [1433] = "MSSQL"
        };

        // Default credentials for network devices
        private static readonly Dictionary<string, List<(string username, string password)>> NetworkDeviceCredentials = new()
        {
            ["Cisco"] = new List<(string, string)>
            {
                ("admin", "admin"),
                ("cisco", "cisco"),
                ("admin", "cisco"),
                ("admin", ""),
                ("", ""),
                ("enable", ""),
                ("root", "cisco")
            },
            ["Mikrotik"] = new List<(string, string)>
            {
                ("admin", ""),
                ("admin", "admin"),
                ("admin", "123456"),
                ("user", ""),
                ("guest", "")
            },
            ["Ubiquiti"] = new List<(string, string)>
            {
                ("ubnt", "ubnt"),
                ("admin", "admin"),
                ("root", "ubnt"),
                ("admin", "")
            },
            ["Netgear"] = new List<(string, string)>
            {
                ("admin", "password"),
                ("admin", "admin"),
                ("admin", ""),
                ("netgear", "password")
            },
            ["Default"] = new List<(string, string)>
            {
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("admin", ""),
                ("root", "root"),
                ("guest", "guest"),
                ("user", "user")
            }
        };

        /// <summary>
        /// Initializes a new instance of the NetworkInfrastructureScanner class
        /// </summary>
        /// <param name="timeout">Connection timeout in milliseconds</param>
        public NetworkInfrastructureScanner(int timeout = 5000)
        {
            _timeout = timeout;
        }

        /// <summary>
        /// Performs comprehensive network infrastructure vulnerability scan
        /// </summary>
        /// <param name="host">Target host to scan</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of infrastructure vulnerabilities found</returns>
        public async Task<List<VulnerabilityInfo>> ScanNetworkInfrastructureAsync(string host, CancellationToken cancellationToken = default)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            AnsiConsole.WriteLine($"[yellow]🔍 Scanning network infrastructure for {host}[/]");

            try
            {
                // 1. Device fingerprinting and identification
                var deviceInfo = await IdentifyNetworkDeviceAsync(host, cancellationToken);
                
                // 2. Check for common network vulnerabilities
                var commonVulns = await ScanCommonNetworkVulnerabilitiesAsync(host, deviceInfo, cancellationToken);
                vulnerabilities.AddRange(commonVulns);

                // 3. Check for insecure protocols
                var protocolVulns = await ScanInsecureProtocolsAsync(host, cancellationToken);
                vulnerabilities.AddRange(protocolVulns);

                // 4. Check for default credentials
                var credentialVulns = await ScanDefaultCredentialsAsync(host, deviceInfo, cancellationToken);
                vulnerabilities.AddRange(credentialVulns);

                // 5. Check for IoT specific vulnerabilities
                var iotVulns = await ScanIoTVulnerabilitiesAsync(host, cancellationToken);
                vulnerabilities.AddRange(iotVulns);

                // 6. Check for industrial control system vulnerabilities
                var icsVulns = await ScanIndustrialControlVulnerabilitiesAsync(host, cancellationToken);
                vulnerabilities.AddRange(icsVulns);

                // 7. SNMP enumeration and vulnerabilities
                var snmpVulns = await ScanSNMPVulnerabilitiesAsync(host, cancellationToken);
                vulnerabilities.AddRange(snmpVulns);

                AnsiConsole.WriteLine($"[green]✅ Infrastructure scan completed. Found {vulnerabilities.Count} potential issues.[/]");
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[red]❌ Error during infrastructure scan: {ex.Message}[/]");
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Identifies the type of network device based on service fingerprinting
        /// </summary>
        private async Task<NetworkDeviceInfo> IdentifyNetworkDeviceAsync(string host, CancellationToken cancellationToken)
        {
            var deviceInfo = new NetworkDeviceInfo { Host = host };

            foreach (var signature in DeviceSignatures)
            {
                try
                {
                    bool matchFound = false;

                    // Check ports
                    foreach (var port in signature.Value.Ports.Take(3)) // Limit port checks
                    {
                        if (await IsPortOpenAsync(host, port, cancellationToken))
                        {
                            deviceInfo.OpenPorts.Add(port);
                            
                            // Try to get banner information
                            var banner = await GetServiceBannerAsync(host, port, cancellationToken);
                            if (!string.IsNullOrEmpty(banner))
                            {
                                deviceInfo.ServiceBanners[port] = banner;
                                
                                // Check if banner matches device signature
                                if (signature.Value.BannerPatterns.Any(pattern => 
                                    banner.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                                {
                                    deviceInfo.DeviceType = signature.Key;
                                    deviceInfo.VulnerabilityLevel = signature.Value.VulnerabilityLevel;
                                    matchFound = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (matchFound) break;
                }
                catch
                {
                    // Continue with next signature
                }
            }

            return deviceInfo;
        }

        /// <summary>
        /// Scans for common network device vulnerabilities
        /// </summary>
        private async Task<List<VulnerabilityInfo>> ScanCommonNetworkVulnerabilitiesAsync(string host, NetworkDeviceInfo deviceInfo, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            // Check for exposed management interfaces
            if (deviceInfo.OpenPorts.Contains(80) || deviceInfo.OpenPorts.Contains(443))
            {
                vulnerabilities.Add(new VulnerabilityInfo
                {
                    Host = host,
                    Port = deviceInfo.OpenPorts.Contains(443) ? 443 : 80,
                    ServiceName = "HTTP Management",
                    Severity = VulnerabilitySeverity.Medium,
                    Title = "Network Device Management Interface Exposed",
                    Description = "Network device web management interface is accessible from external networks.",
                    RecommendedFix = "Restrict management interface access to authorized networks only using ACLs or firewall rules."
                });
            }

            // Check for specific device vulnerabilities based on type
            if (!string.IsNullOrEmpty(deviceInfo.DeviceType))
            {
                var deviceVulns = await ScanDeviceSpecificVulnerabilitiesAsync(host, deviceInfo, cancellationToken);
                vulnerabilities.AddRange(deviceVulns);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for insecure network protocols
        /// </summary>
        private async Task<List<VulnerabilityInfo>> ScanInsecureProtocolsAsync(string host, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            var insecureProtocols = new Dictionary<int, (string service, VulnerabilitySeverity severity, string description)>
            {
                [21] = ("FTP", VulnerabilitySeverity.Medium, "FTP transmits credentials in plaintext"),
                [23] = ("Telnet", VulnerabilitySeverity.High, "Telnet transmits all data including credentials in plaintext"),
                [69] = ("TFTP", VulnerabilitySeverity.Medium, "TFTP has no authentication and transmits data in plaintext"),
                [79] = ("Finger", VulnerabilitySeverity.Low, "Finger protocol can disclose user information"),
                [111] = ("RPC", VulnerabilitySeverity.Medium, "RPC can be exploited for information gathering and attacks"),
                [512] = ("Rexec", VulnerabilitySeverity.High, "Rexec allows remote command execution with weak authentication"),
                [513] = ("Rlogin", VulnerabilitySeverity.High, "Rlogin provides remote access with weak authentication"),
                [514] = ("RSH", VulnerabilitySeverity.High, "Remote shell provides command execution without encryption")
            };

            foreach (var protocol in insecureProtocols)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    if (await IsPortOpenAsync(host, protocol.Key, cancellationToken))
                    {
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Host = host,
                            Port = protocol.Key,
                            ServiceName = protocol.Value.service,
                            Severity = protocol.Value.severity,
                            Title = $"Insecure Protocol: {protocol.Value.service}",
                            Description = protocol.Value.description + ". This poses security risks including eavesdropping and credential theft.",
                            RecommendedFix = $"Disable {protocol.Value.service} service and use secure alternatives like SSH or HTTPS."
                        });
                    }
                }
                catch
                {
                    // Continue with next protocol
                }

                await Task.Delay(50, cancellationToken);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Tests for default credentials on network devices
        /// </summary>
        private async Task<List<VulnerabilityInfo>> ScanDefaultCredentialsAsync(string host, NetworkDeviceInfo deviceInfo, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            // Determine which credential set to use based on device type
            var credentialSet = "Default";
            if (!string.IsNullOrEmpty(deviceInfo.DeviceType))
            {
                var deviceType = deviceInfo.DeviceType.Split(' ')[0]; // Get first word (e.g., "Cisco" from "Cisco Router")
                if (NetworkDeviceCredentials.ContainsKey(deviceType))
                {
                    credentialSet = deviceType;
                }
            }

            // Test HTTP/HTTPS management interfaces for default credentials
            var webPorts = deviceInfo.OpenPorts.Where(p => p == 80 || p == 443 || p == 8080 || p == 8443).ToList();
            foreach (var port in webPorts)
            {
                if (cancellationToken.IsCancellationRequested) break;

                var credVulns = await TestWebInterfaceCredentialsAsync(host, port, credentialSet, cancellationToken);
                vulnerabilities.AddRange(credVulns);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for IoT device specific vulnerabilities
        /// </summary>
        private async Task<List<VulnerabilityInfo>> ScanIoTVulnerabilitiesAsync(string host, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            foreach (var iotService in IoTServicePorts)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    if (await IsPortOpenAsync(host, iotService.Key, cancellationToken))
                    {
                        var severity = DetermineIoTServiceSeverity(iotService.Value);
                        
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Host = host,
                            Port = iotService.Key,
                            ServiceName = iotService.Value,
                            Severity = severity,
                            Title = $"Exposed IoT Service: {iotService.Value}",
                            Description = $"IoT service '{iotService.Value}' is accessible, potentially exposing device functionality or data.",
                            RecommendedFix = "Secure IoT services with proper authentication, encryption, and network segmentation."
                        });

                        // Specific checks for certain IoT protocols
                        if (iotService.Value.Contains("MQTT"))
                        {
                            var mqttVulns = await CheckMQTTVulnerabilitiesAsync(host, iotService.Key, cancellationToken);
                            vulnerabilities.AddRange(mqttVulns);
                        }
                        else if (iotService.Value.Contains("UPnP"))
                        {
                            var upnpVulns = await CheckUPnPVulnerabilitiesAsync(host, iotService.Key, cancellationToken);
                            vulnerabilities.AddRange(upnpVulns);
                        }
                    }
                }
                catch
                {
                    // Continue with next service
                }

                await Task.Delay(50, cancellationToken);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for industrial control system vulnerabilities
        /// </summary>
        private async Task<List<VulnerabilityInfo>> ScanIndustrialControlVulnerabilitiesAsync(string host, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            var industrialPorts = new Dictionary<int, string>
            {
                [502] = "Modbus",
                [1911] = "Tridium Fox",
                [2404] = "IEC 61850 MMS",
                [20000] = "DNP3",
                [44818] = "EtherNet/IP",
                [4840] = "OPC-UA",
                [102] = "IEC 60870-5-104"
            };

            foreach (var industrialProtocol in industrialPorts)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    if (await IsPortOpenAsync(host, industrialProtocol.Key, cancellationToken))
                    {
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Host = host,
                            Port = industrialProtocol.Key,
                            ServiceName = industrialProtocol.Value,
                            Severity = VulnerabilitySeverity.Critical,
                            Title = $"Exposed Industrial Protocol: {industrialProtocol.Value}",
                            Description = $"Industrial control protocol '{industrialProtocol.Value}' is accessible from external networks, potentially allowing unauthorized control of critical infrastructure.",
                            RecommendedFix = "Isolate industrial control systems from public networks using firewalls, VPNs, and network segmentation. Implement proper authentication and monitoring."
                        });
                    }
                }
                catch
                {
                    // Continue with next protocol
                }

                await Task.Delay(100, cancellationToken);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for SNMP vulnerabilities
        /// </summary>
        private async Task<List<VulnerabilityInfo>> ScanSNMPVulnerabilitiesAsync(string host, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            try
            {
                if (await IsPortOpenAsync(host, 161, cancellationToken))
                {
                    // Test for common SNMP community strings
                    var communityStrings = new[] { "public", "private", "community", "read", "write", "admin", "test" };
                    
                    foreach (var community in communityStrings.Take(3)) // Limit testing
                    {
                        if (cancellationToken.IsCancellationRequested) break;

                        if (await TestSNMPCommunityAsync(host, community, cancellationToken))
                        {
                            var severity = community == "public" ? VulnerabilitySeverity.High : VulnerabilitySeverity.Critical;
                            
                            vulnerabilities.Add(new VulnerabilityInfo
                            {
                                Host = host,
                                Port = 161,
                                ServiceName = "SNMP",
                                Severity = severity,
                                Title = $"SNMP Weak Community String: {community}",
                                Description = $"SNMP service accepts the weak community string '{community}', potentially allowing unauthorized access to device information and configuration.",
                                RecommendedFix = "Use strong, unique SNMP community strings or preferably upgrade to SNMPv3 with proper authentication and encryption."
                            });
                            
                            break; // Don't test more if we find one working
                        }

                        await Task.Delay(200, cancellationToken);
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[yellow]⚠️ Error testing SNMP vulnerabilities: {ex.Message}[/]");
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for device-specific vulnerabilities
        /// </summary>
        private async Task<List<VulnerabilityInfo>> ScanDeviceSpecificVulnerabilitiesAsync(string host, NetworkDeviceInfo deviceInfo, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            switch (deviceInfo.DeviceType?.ToLowerInvariant())
            {
                case var type when !string.IsNullOrEmpty(type) && type.Contains("cisco"):
                    vulnerabilities.AddRange(await ScanCiscoVulnerabilitiesAsync(host, deviceInfo, cancellationToken));
                    break;
                case var type when !string.IsNullOrEmpty(type) && type.Contains("mikrotik"):
                    vulnerabilities.AddRange(await ScanMikroTikVulnerabilitiesAsync(host, deviceInfo, cancellationToken));
                    break;
                case var type when !string.IsNullOrEmpty(type) && type.Contains("ubiquiti"):
                    vulnerabilities.AddRange(await ScanUbiquitiVulnerabilitiesAsync(host, deviceInfo, cancellationToken));
                    break;
            }

            return vulnerabilities;
        }

        #region Device-Specific Vulnerability Scanners

        private async Task<List<VulnerabilityInfo>> ScanCiscoVulnerabilitiesAsync(string host, NetworkDeviceInfo deviceInfo, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            // Cisco-specific vulnerability checks
            if (deviceInfo.OpenPorts.Contains(23))
            {
                vulnerabilities.Add(new VulnerabilityInfo
                {
                    Host = host,
                    Port = 23,
                    ServiceName = "Cisco Telnet",
                    Severity = VulnerabilitySeverity.High,
                    Title = "Cisco Device Telnet Access Enabled",
                    Description = "Cisco device has Telnet enabled, which transmits configuration commands and credentials in plaintext.",
                    RecommendedFix = "Disable Telnet access using 'transport input ssh' and ensure SSH is properly configured."
                });
            }

            if (deviceInfo.OpenPorts.Contains(80))
            {
                vulnerabilities.Add(new VulnerabilityInfo
                {
                    Host = host,
                    Port = 80,
                    ServiceName = "Cisco HTTP",
                    Severity = VulnerabilitySeverity.Medium,
                    Title = "Cisco HTTP Management Interface",
                    Description = "Cisco device HTTP management interface is accessible without encryption.",
                    RecommendedFix = "Enable HTTPS management using 'ip http secure-server' and disable HTTP with 'no ip http server'."
                });
            }

            await Task.Delay(50, cancellationToken); // Simulate processing time
            return vulnerabilities;
        }

        private async Task<List<VulnerabilityInfo>> ScanMikroTikVulnerabilitiesAsync(string host, NetworkDeviceInfo deviceInfo, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            // MikroTik-specific vulnerability checks
            if (deviceInfo.OpenPorts.Contains(8291))
            {
                vulnerabilities.Add(new VulnerabilityInfo
                {
                    Host = host,
                    Port = 8291,
                    ServiceName = "MikroTik Winbox",
                    Severity = VulnerabilitySeverity.High,
                    Title = "MikroTik Winbox Interface Exposed",
                    Description = "MikroTik Winbox management interface is accessible. Historical vulnerabilities include CVE-2018-14847 for credential disclosure.",
                    RecommendedFix = "Restrict Winbox access to authorized networks only and ensure RouterOS is updated to the latest version."
                });
            }

            if (deviceInfo.OpenPorts.Contains(8728))
            {
                vulnerabilities.Add(new VulnerabilityInfo
                {
                    Host = host,
                    Port = 8728,
                    ServiceName = "MikroTik API",
                    Severity = VulnerabilitySeverity.Medium,
                    Title = "MikroTik API Interface Exposed",
                    Description = "MikroTik API interface is accessible, allowing programmatic access to router configuration.",
                    RecommendedFix = "Secure API access with strong authentication and restrict access to authorized clients only."
                });
            }

            await Task.Delay(50, cancellationToken);
            return vulnerabilities;
        }

        private async Task<List<VulnerabilityInfo>> ScanUbiquitiVulnerabilitiesAsync(string host, NetworkDeviceInfo deviceInfo, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            // Check for default SSH credentials
            if (deviceInfo.OpenPorts.Contains(22))
            {
                vulnerabilities.Add(new VulnerabilityInfo
                {
                    Host = host,
                    Port = 22,
                    ServiceName = "Ubiquiti SSH",
                    Severity = VulnerabilitySeverity.Medium,
                    Title = "Ubiquiti Device SSH Access",
                    Description = "Ubiquiti device has SSH enabled. Ensure default credentials have been changed.",
                    RecommendedFix = "Change default SSH credentials (ubnt/ubnt) and consider using SSH keys for authentication."
                });
            }

            await Task.Delay(50, cancellationToken);
            return vulnerabilities;
        }

        #endregion

        #region Helper Methods

        private async Task<bool> IsPortOpenAsync(string host, int port, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(_timeout, cancellationToken);
                
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                return completedTask == connectTask && client.Connected;
            }
            catch
            {
                return false;
            }
        }

        private async Task<string> GetServiceBannerAsync(string host, int port, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port);
                using var stream = client.GetStream();
                
                // Wait for banner or send a simple request
                var buffer = new byte[1024];
                stream.ReadTimeout = 3000;
                
                try
                {
                    var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    if (bytesRead > 0)
                    {
                        return Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    }
                }
                catch
                {
                    // Try sending a simple HTTP request for web services
                    if (port == 80 || port == 443 || port == 8080 || port == 8443)
                    {
                        var httpRequest = Encoding.UTF8.GetBytes("GET / HTTP/1.0\r\n\r\n");
                        await stream.WriteAsync(httpRequest, 0, httpRequest.Length, cancellationToken);
                        
                        var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                        if (bytesRead > 0)
                        {
                            return Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        }
                    }
                }
            }
            catch
            {
                // Could not get banner
            }
            
            return "";
        }

        private VulnerabilitySeverity DetermineIoTServiceSeverity(string serviceName)
        {
            var criticalServices = new[] { "MongoDB", "Redis", "Elasticsearch", "MySQL", "PostgreSQL", "MSSQL" };
            var highServices = new[] { "MQTT", "HTTP Alt", "HTTPS Alt", "Management" };
            
            if (criticalServices.Any(s => serviceName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                return VulnerabilitySeverity.Critical;
            if (highServices.Any(s => serviceName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                return VulnerabilitySeverity.High;
                
            return VulnerabilitySeverity.Medium;
        }

        private async Task<List<VulnerabilityInfo>> TestWebInterfaceCredentialsAsync(string host, int port, string credentialSet, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();
            
            // Placeholder for actual HTTP authentication testing
            // In a real implementation, this would test HTTP Basic Auth, form-based auth, etc.
            await Task.Delay(100, cancellationToken);
            
            return vulnerabilities;
        }

        private async Task<List<VulnerabilityInfo>> CheckMQTTVulnerabilitiesAsync(string host, int port, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            try
            {
                // Test MQTT connection without credentials
                using var client = new TcpClient();
                await client.ConnectAsync(host, port);
                
                // MQTT connection packet (simplified)
                var connectPacket = new byte[] { 0x10, 0x0C, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x00, 0x00, 0x3C, 0x00, 0x00 };
                using var stream = client.GetStream();
                
                await stream.WriteAsync(connectPacket, 0, connectPacket.Length, cancellationToken);
                
                var buffer = new byte[256];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                
                // Check for successful connection response
                if (bytesRead > 0 && buffer[0] == 0x20 && buffer[3] == 0x00)
                {
                    vulnerabilities.Add(new VulnerabilityInfo
                    {
                        Host = host,
                        Port = port,
                        ServiceName = "MQTT",
                        Severity = VulnerabilitySeverity.High,
                        Title = "MQTT Broker Allows Anonymous Connections",
                        Description = "MQTT broker accepts connections without authentication, potentially exposing IoT device communications.",
                        RecommendedFix = "Configure MQTT broker to require username/password authentication and use TLS encryption."
                    });
                }
            }
            catch
            {
                // MQTT test failed
            }

            return vulnerabilities;
        }

        private async Task<List<VulnerabilityInfo>> CheckUPnPVulnerabilitiesAsync(string host, int port, CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            vulnerabilities.Add(new VulnerabilityInfo
            {
                Host = host,
                Port = port,
                ServiceName = "UPnP",
                Severity = VulnerabilitySeverity.Medium,
                Title = "UPnP Service Exposed",
                Description = "UPnP service is accessible, which can be exploited for port manipulation and information disclosure.",
                RecommendedFix = "Disable UPnP if not required, or restrict UPnP access to trusted networks only."
            });

            await Task.Delay(50, cancellationToken);
            return vulnerabilities;
        }

        private async Task<bool> TestSNMPCommunityAsync(string host, string community, CancellationToken cancellationToken)
        {
            try
            {
                // Simplified SNMP v1 GET request for sysDescr (1.3.6.1.2.1.1.1.0)
                // In a real implementation, use a proper SNMP library
                using var client = new UdpClient();
                var remoteEP = new IPEndPoint(IPAddress.Parse(host), 161);
                
                // Basic SNMP packet structure (placeholder)
                var snmpPacket = new byte[]
                {
                    0x30, 0x19, // SEQUENCE
                    0x02, 0x01, 0x00, // version (v1)
                    0x04, (byte)community.Length // community string length
                };
                
                var communityBytes = Encoding.ASCII.GetBytes(community);
                var packet = new byte[snmpPacket.Length + communityBytes.Length + 10];
                Array.Copy(snmpPacket, packet, snmpPacket.Length);
                Array.Copy(communityBytes, 0, packet, snmpPacket.Length, communityBytes.Length);
                
                await client.SendAsync(packet, packet.Length, remoteEP);
                
                var timeoutTask = Task.Delay(2000, cancellationToken);
                var receiveTask = client.ReceiveAsync();
                
                var completedTask = await Task.WhenAny(receiveTask, timeoutTask);
                
                return completedTask == receiveTask;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        /// <summary>
        /// Information about a discovered network device
        /// </summary>
        private class NetworkDeviceInfo
        {
            public string Host { get; set; } = "";
            public string DeviceType { get; set; } = "";
            public VulnerabilitySeverity VulnerabilityLevel { get; set; } = VulnerabilitySeverity.Medium;
            public List<int> OpenPorts { get; set; } = new List<int>();
            public Dictionary<int, string> ServiceBanners { get; set; } = new Dictionary<int, string>();
        }

        /// <summary>
        /// Device signature for identification
        /// </summary>
        private class InfrastructureSignature
        {
            public int[] Ports { get; set; } = Array.Empty<int>();
            public string[] BannerPatterns { get; set; } = Array.Empty<string>();
            public string[] HttpTitlePatterns { get; set; } = Array.Empty<string>();
            public VulnerabilitySeverity VulnerabilityLevel { get; set; } = VulnerabilitySeverity.Medium;
        }
    }
}
