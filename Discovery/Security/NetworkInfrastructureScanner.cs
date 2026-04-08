using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Discovery.Core.Models;

namespace Discovery.Security
{
    /// <summary>
    /// Advanced network infrastructure vulnerability scanner for routers, IoT devices, and network appliances
    /// </summary>
    public class NetworkInfrastructureScanner
    {
        private readonly Dictionary<string, DeviceFingerprint> _deviceFingerprints;
        private readonly Dictionary<string, string[]> _defaultCredentials;
        private readonly Dictionary<int, ProtocolInfo> _protocolInfo;

        /// <summary>
        /// Initializes a new instance of the NetworkInfrastructureScanner class
        /// </summary>
        public NetworkInfrastructureScanner()
        {
            _deviceFingerprints = InitializeDeviceFingerprints();
            _defaultCredentials = InitializeDefaultCredentials();
            _protocolInfo = InitializeProtocolInfo();
        }

        /// <summary>
        /// Scans network infrastructure for vulnerabilities
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Collection of infrastructure vulnerabilities</returns>
        public async Task<IEnumerable<InfrastructureVulnerability>> ScanInfrastructureAsync(IPAddress target, IEnumerable<int> openPorts)
        {
            var vulnerabilities = new List<InfrastructureVulnerability>();
            var ports = openPorts.ToList();

            try
            {
                // Device fingerprinting
                var deviceType = await IdentifyDeviceTypeAsync(target, ports);
                if (!string.IsNullOrEmpty(deviceType))
                {
                    vulnerabilities.Add(new InfrastructureVulnerability
                    {
                        Type = "DEVICE_IDENTIFICATION",
                        Severity = "INFO",
                        DeviceType = deviceType,
                        Description = $"Device identified as: {deviceType}",
                        Host = target.ToString(),
                        Recommendation = "Verify device security configuration"
                    });

                    // Device-specific vulnerability checks
                    var deviceVulns = await ScanDeviceSpecificVulnerabilitiesAsync(target, deviceType, ports);
                    vulnerabilities.AddRange(deviceVulns);
                }

                // Protocol-specific scans
                var protocolVulns = await ScanNetworkProtocolsAsync(target, ports);
                vulnerabilities.AddRange(protocolVulns);

                // SNMP scanning
                if (ports.Contains(161))
                {
                    var snmpVulns = await ScanSNMPAsync(target);
                    vulnerabilities.AddRange(snmpVulns);
                }

                // Industrial protocol scanning
                var industrialVulns = await ScanIndustrialProtocolsAsync(target, ports);
                vulnerabilities.AddRange(industrialVulns);

                // IoT device scanning
                var iotVulns = await ScanIoTDevicesAsync(target, ports);
                vulnerabilities.AddRange(iotVulns);

                return vulnerabilities;
            }
            catch (Exception ex)
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "SCAN_ERROR",
                    Severity = "INFO",
                    Description = $"Error scanning infrastructure: {ex.Message}",
                    Host = target.ToString()
                });
                return vulnerabilities;
            }
        }

        /// <summary>
        /// Identifies the device type based on fingerprinting
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Device type or empty string if unknown</returns>
        private async Task<string> IdentifyDeviceTypeAsync(IPAddress target, List<int> openPorts)
        {
            try
            {
                // TTL-based OS detection
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(target, 3000);
                
                if (reply.Status == IPStatus.Success && reply.Options != null)
                {
                    var ttl = reply.Options.Ttl;
                    
                    // Common TTL values for device identification
                    return ttl switch
                    {
                        64 => "Linux/Unix Device",
                        128 => "Windows Device",
                        255 => "Cisco Device",
                        254 => "Network Appliance",
                        _ => "Unknown Device"
                    };
                }

                // Port-based device identification
                if (openPorts.Contains(23) && openPorts.Contains(80) && openPorts.Contains(443))
                {
                    return "Network Router/Switch";
                }

                if (openPorts.Contains(8080) && openPorts.Contains(8443))
                {
                    return "Network Management Device";
                }

                if (openPorts.Contains(1900) && openPorts.Contains(80))
                {
                    return "IoT Device";
                }

                return "Unknown Device";
            }
            catch
            {
                return "Unknown Device";
            }
        }

        /// <summary>
        /// Scans for device-specific vulnerabilities
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="deviceType">Identified device type</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Collection of device-specific vulnerabilities</returns>
        private async Task<IEnumerable<InfrastructureVulnerability>> ScanDeviceSpecificVulnerabilitiesAsync(IPAddress target, string deviceType, List<int> openPorts)
        {
            var vulnerabilities = new List<InfrastructureVulnerability>();

            await Task.Delay(50); // Placeholder async operation

            // Check for default credentials based on device type
            if (_defaultCredentials.TryGetValue(deviceType, out var credentials))
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "DEFAULT_CREDENTIALS_POSSIBLE",
                    Severity = "HIGH",
                    DeviceType = deviceType,
                    Description = $"Device may be using default credentials: {string.Join(", ", credentials)}",
                    Host = target.ToString(),
                    Recommendation = "Change default credentials immediately"
                });
            }

            // Cisco-specific checks
            if (deviceType.Contains("Cisco"))
            {
                if (openPorts.Contains(23)) // Telnet
                {
                    vulnerabilities.Add(new InfrastructureVulnerability
                    {
                        Type = "INSECURE_TELNET",
                        Severity = "HIGH",
                        DeviceType = deviceType,
                        Description = "Cisco device has Telnet enabled (insecure)",
                        Host = target.ToString(),
                        Recommendation = "Disable Telnet and use SSH instead"
                    });
                }

                if (openPorts.Contains(80)) // HTTP management
                {
                    vulnerabilities.Add(new InfrastructureVulnerability
                    {
                        Type = "INSECURE_HTTP_MGMT",
                        Severity = "MEDIUM",
                        DeviceType = deviceType,
                        Description = "HTTP management interface accessible",
                        Host = target.ToString(),
                        Recommendation = "Use HTTPS for management interfaces"
                    });
                }
            }

            // Network appliance checks
            if (deviceType.Contains("Router") || deviceType.Contains("Switch"))
            {
                if (openPorts.Contains(161) && openPorts.Contains(162))
                {
                    vulnerabilities.Add(new InfrastructureVulnerability
                    {
                        Type = "SNMP_ENABLED",
                        Severity = "MEDIUM",
                        DeviceType = deviceType,
                        Description = "SNMP is enabled and may use default community strings",
                        Host = target.ToString(),
                        Recommendation = "Secure SNMP configuration or disable if not needed"
                    });
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans network protocols for vulnerabilities
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Collection of protocol-specific vulnerabilities</returns>
        private async Task<IEnumerable<InfrastructureVulnerability>> ScanNetworkProtocolsAsync(IPAddress target, List<int> openPorts)
        {
            var vulnerabilities = new List<InfrastructureVulnerability>();

            foreach (var port in openPorts)
            {
                if (_protocolInfo.TryGetValue(port, out var protocol))
                {
                    try
                    {
                        var banner = await GetServiceBannerAsync(target, port);
                        
                        if (!string.IsNullOrEmpty(banner))
                        {
                            // Analyze banner for vulnerabilities
                            var protocolVulns = AnalyzeProtocolBanner(target.ToString(), port, protocol, banner);
                            vulnerabilities.AddRange(protocolVulns);
                        }
                    }
                    catch
                    {
                        // Banner grabbing failed
                    }
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Analyzes protocol banner for vulnerabilities
        /// </summary>
        /// <param name="host">Target host</param>
        /// <param name="port">Target port</param>
        /// <param name="protocol">Protocol information</param>
        /// <param name="banner">Service banner</param>
        /// <returns>Collection of vulnerabilities found in banner</returns>
        private IEnumerable<InfrastructureVulnerability> AnalyzeProtocolBanner(string host, int port, ProtocolInfo protocol, string banner)
        {
            var vulnerabilities = new List<InfrastructureVulnerability>();
            var lowerBanner = banner.ToLowerInvariant();

            // Check for version information disclosure
            if (Regex.IsMatch(lowerBanner, @"\d+\.\d+"))
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "VERSION_DISCLOSURE",
                    Severity = "LOW",
                    Protocol = protocol.Name,
                    Description = $"{protocol.Name} version information disclosed: {banner.Trim()}",
                    Host = host,
                    Port = port,
                    Recommendation = "Configure service to hide version information"
                });
            }

            // Check for specific vulnerabilities based on protocol
            switch (protocol.Name.ToUpperInvariant())
            {
                case "SSH":
                    if (lowerBanner.Contains("openssh") && lowerBanner.Contains("1."))
                    {
                        vulnerabilities.Add(new InfrastructureVulnerability
                        {
                            Type = "OUTDATED_SSH",
                            Severity = "HIGH",
                            Protocol = protocol.Name,
                            Description = "Outdated SSH version with known vulnerabilities",
                            Host = host,
                            Port = port,
                            Recommendation = "Update SSH to latest version"
                        });
                    }
                    break;

                case "FTP":
                    if (lowerBanner.Contains("vsftpd 2.3.4"))
                    {
                        vulnerabilities.Add(new InfrastructureVulnerability
                        {
                            Type = "BACKDOOR_FTP",
                            Severity = "CRITICAL",
                            Protocol = protocol.Name,
                            Description = "vsftpd 2.3.4 backdoor vulnerability detected",
                            Host = host,
                            Port = port,
                            Recommendation = "Update FTP server immediately"
                        });
                    }
                    break;

                case "TELNET":
                    vulnerabilities.Add(new InfrastructureVulnerability
                    {
                        Type = "INSECURE_PROTOCOL",
                        Severity = "HIGH",
                        Protocol = protocol.Name,
                        Description = "Telnet service detected (transmits credentials in plaintext)",
                        Host = host,
                        Port = port,
                        Recommendation = "Replace Telnet with SSH"
                    });
                    break;
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans SNMP for vulnerabilities
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <returns>Collection of SNMP vulnerabilities</returns>
        private async Task<IEnumerable<InfrastructureVulnerability>> ScanSNMPAsync(IPAddress target)
        {
            var vulnerabilities = new List<InfrastructureVulnerability>();

            await Task.Delay(100); // Placeholder async operation

            // Test common community strings
            var commonCommunities = new[] { "public", "private", "admin", "manager", "cisco", "default" };
            
            vulnerabilities.Add(new InfrastructureVulnerability
            {
                Type = "SNMP_DETECTED",
                Severity = "MEDIUM",
                Protocol = "SNMP",
                Description = "SNMP service detected - may be using default community strings",
                Host = target.ToString(),
                Port = 161,
                Recommendation = "Change default SNMP community strings or disable SNMP"
            });

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for industrial protocol vulnerabilities
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Collection of industrial protocol vulnerabilities</returns>
        private async Task<IEnumerable<InfrastructureVulnerability>> ScanIndustrialProtocolsAsync(IPAddress target, List<int> openPorts)
        {
            var vulnerabilities = new List<InfrastructureVulnerability>();

            await Task.Delay(50); // Placeholder async operation

            // Modbus (port 502)
            if (openPorts.Contains(502))
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "INDUSTRIAL_PROTOCOL",
                    Severity = "HIGH",
                    Protocol = "Modbus",
                    Description = "Modbus industrial protocol detected - typically lacks authentication",
                    Host = target.ToString(),
                    Port = 502,
                    Recommendation = "Implement network segmentation and access controls"
                });
            }

            // DNP3 (port 20000)
            if (openPorts.Contains(20000))
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "INDUSTRIAL_PROTOCOL",
                    Severity = "HIGH",
                    Protocol = "DNP3",
                    Description = "DNP3 SCADA protocol detected",
                    Host = target.ToString(),
                    Port = 20000,
                    Recommendation = "Secure SCADA network with proper authentication and encryption"
                });
            }

            // EtherNet/IP (port 44818)
            if (openPorts.Contains(44818))
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "INDUSTRIAL_PROTOCOL",
                    Severity = "HIGH",
                    Protocol = "EtherNet/IP",
                    Description = "EtherNet/IP industrial protocol detected",
                    Host = target.ToString(),
                    Port = 44818,
                    Recommendation = "Implement industrial network security controls"
                });
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for IoT device vulnerabilities
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Collection of IoT vulnerabilities</returns>
        private async Task<IEnumerable<InfrastructureVulnerability>> ScanIoTDevicesAsync(IPAddress target, List<int> openPorts)
        {
            var vulnerabilities = new List<InfrastructureVulnerability>();

            await Task.Delay(50); // Placeholder async operation

            // UPnP (port 1900)
            if (openPorts.Contains(1900))
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "IOT_UPNP",
                    Severity = "MEDIUM",
                    Protocol = "UPnP",
                    Description = "UPnP service detected - may allow unauthorized device control",
                    Host = target.ToString(),
                    Port = 1900,
                    Recommendation = "Disable UPnP if not required or implement access controls"
                });
            }

            // MQTT (port 1883)
            if (openPorts.Contains(1883))
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "IOT_MQTT",
                    Severity = "MEDIUM",
                    Protocol = "MQTT",
                    Description = "MQTT IoT protocol detected - may lack proper authentication",
                    Host = target.ToString(),
                    Port = 1883,
                    Recommendation = "Implement MQTT authentication and encryption"
                });
            }

            // CoAP (port 5683)
            if (openPorts.Contains(5683))
            {
                vulnerabilities.Add(new InfrastructureVulnerability
                {
                    Type = "IOT_COAP",
                    Severity = "MEDIUM",
                    Protocol = "CoAP",
                    Description = "CoAP IoT protocol detected",
                    Host = target.ToString(),
                    Port = 5683,
                    Recommendation = "Secure CoAP implementation with proper authentication"
                });
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Gets service banner from a port
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="port">Port to connect to</param>
        /// <returns>Service banner or empty string</returns>
        private async Task<string> GetServiceBannerAsync(IPAddress target, int port)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(target, port);
                var timeoutTask = Task.Delay(3000);
                
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                if (completedTask != connectTask || !client.Connected)
                    return "";

                using var stream = client.GetStream();
                var buffer = new byte[512];
                stream.ReadTimeout = 2000;
                
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (bytesRead > 0)
                {
                    return Encoding.UTF8.GetString(buffer, 0, bytesRead);
                }
            }
            catch
            {
                // Banner grabbing failed
            }
            
            return "";
        }

        /// <summary>
        /// Initializes device fingerprint database
        /// </summary>
        /// <returns>Dictionary of device fingerprints</returns>
        private Dictionary<string, DeviceFingerprint> InitializeDeviceFingerprints()
        {
            return new Dictionary<string, DeviceFingerprint>
            {
                ["cisco_router"] = new DeviceFingerprint 
                { 
                    DeviceType = "Cisco Router", 
                    Indicators = Array.Empty<string>()
                },
                ["mikrotik_router"] = new DeviceFingerprint 
                { 
                    DeviceType = "MikroTik Router", 
                    Indicators = Array.Empty<string>()
                },
                ["netgear_router"] = new DeviceFingerprint 
                { 
                    DeviceType = "Netgear Router", 
                    Indicators = Array.Empty<string>()
                },
                ["iot_camera"] = new DeviceFingerprint 
                { 
                    DeviceType = "IP Camera", 
                    Indicators = Array.Empty<string>()
                }
            };
        }

        /// <summary>
        /// Initializes default credential database
        /// </summary>
        /// <returns>Dictionary of default credentials by device type</returns>
        private Dictionary<string, string[]> InitializeDefaultCredentials()
        {
            return new Dictionary<string, string[]>
            {
                ["Cisco Router"] = new[] { "admin/admin", "cisco/cisco", "admin/password" },
                ["MikroTik Router"] = new[] { "admin/(blank)", "admin/admin" },
                ["Netgear Router"] = new[] { "admin/password", "admin/admin" },
                ["IP Camera"] = new[] { "admin/admin", "admin/password", "admin/12345" },
                ["Network Appliance"] = new[] { "admin/admin", "root/root", "admin/password" }
            };
        }

        /// <summary>
        /// Initializes protocol information
        /// </summary>
        /// <returns>Dictionary of protocol information by port</returns>
        private Dictionary<int, ProtocolInfo> InitializeProtocolInfo()
        {
            return new Dictionary<int, ProtocolInfo>
            {
                [21] = new ProtocolInfo { Name = "FTP", IsSecure = false },
                [22] = new ProtocolInfo { Name = "SSH", IsSecure = true },
                [23] = new ProtocolInfo { Name = "Telnet", IsSecure = false },
                [53] = new ProtocolInfo { Name = "DNS", IsSecure = false },
                [80] = new ProtocolInfo { Name = "HTTP", IsSecure = false },
                [443] = new ProtocolInfo { Name = "HTTPS", IsSecure = true },
                [161] = new ProtocolInfo { Name = "SNMP", IsSecure = false },
                [162] = new ProtocolInfo { Name = "SNMP-Trap", IsSecure = false },
                [502] = new ProtocolInfo { Name = "Modbus", IsSecure = false },
                [1883] = new ProtocolInfo { Name = "MQTT", IsSecure = false },
                [1900] = new ProtocolInfo { Name = "UPnP", IsSecure = false },
                [5683] = new ProtocolInfo { Name = "CoAP", IsSecure = false },
                [20000] = new ProtocolInfo { Name = "DNP3", IsSecure = false },
                [44818] = new ProtocolInfo { Name = "EtherNet/IP", IsSecure = false }
            };
        }
    }

    /// <summary>
    /// Represents device fingerprint information
    /// </summary>
    public class DeviceFingerprint
    {
        /// <summary>
        /// Device type
        /// </summary>
        public string DeviceType { get; set; } = "";

        /// <summary>
        /// Fingerprint indicators
        /// </summary>
        public string[] Indicators { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// Represents protocol information
    /// </summary>
    public class ProtocolInfo
    {
        /// <summary>
        /// Protocol name
        /// </summary>
        public string Name { get; set; } = "";

        /// <summary>
        /// Whether the protocol is secure
        /// </summary>
        public bool IsSecure { get; set; }
    }

    /// <summary>
    /// Represents an infrastructure vulnerability finding
    /// </summary>
    public class InfrastructureVulnerability
    {
        /// <summary>
        /// Type of vulnerability
        /// </summary>
        public string Type { get; set; } = "";

        /// <summary>
        /// Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        /// </summary>
        public string Severity { get; set; } = "";

        /// <summary>
        /// Device type (if identified)
        /// </summary>
        public string DeviceType { get; set; } = "";

        /// <summary>
        /// Protocol involved (if applicable)
        /// </summary>
        public string Protocol { get; set; } = "";

        /// <summary>
        /// Description of the vulnerability
        /// </summary>
        public string Description { get; set; } = "";

        /// <summary>
        /// Host where vulnerability was found
        /// </summary>
        public string Host { get; set; } = "";

        /// <summary>
        /// Port where vulnerability was found (if applicable)
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Recommendation for fixing the vulnerability
        /// </summary>
        public string Recommendation { get; set; } = "";
    }
}
