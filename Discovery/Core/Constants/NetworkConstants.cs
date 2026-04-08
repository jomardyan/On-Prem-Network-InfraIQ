using System.Collections.Generic;
using System.Linq;

namespace Discovery.Core.Constants
{
    public static class NetworkConstants
    {
        public static readonly Dictionary<int, string> PopularPorts = new Dictionary<int, string>
        {
            { 7, "Echo" },
            { 9, "Discard" },
            { 13, "Daytime" },
            { 17, "QOTD" },
            { 19, "CharGen" },
            { 20, "FTP-Data" },
            { 21, "FTP" },
            { 22, "SSH" },
            { 23, "Telnet" },
            { 25, "SMTP" },
            { 37, "Time" },
            { 42, "Nameserver" },
            { 43, "WHOIS" },
            { 49, "TACACS" },
            { 53, "DNS" },
            { 67, "DHCP-Server" },
            { 68, "DHCP-Client" },
            { 69, "TFTP" },
            { 70, "Gopher" },
            { 79, "Finger" },
            { 80, "HTTP" },
            { 88, "Kerberos" },
            { 102, "ISO-TSAP" },
            { 110, "POP3" },
            { 111, "RPC" },
            { 113, "Auth/Ident" },
            { 119, "NNTP" },
            { 123, "NTP" },
            { 135, "MSRPC" },
            { 137, "NetBIOS-NS" },
            { 138, "NetBIOS-DGM" },
            { 139, "NetBIOS-SSN" },
            { 143, "IMAP" },
            { 161, "SNMP" },
            { 162, "SNMP-Trap" },
            { 179, "BGP" },
            { 194, "IRC" },
            { 201, "AppleTalk" },
            { 213, "IPX" },
            { 220, "IMAP3" },
            { 389, "LDAP" },
            { 443, "HTTPS" },
            { 444, "SNPP" },
            { 445, "SMB" },
            { 464, "Kerberos-Passwd" },
            { 465, "SMTPS" },
            { 500, "IKE/IPSec" },
            { 512, "Rexec" },
            { 513, "Rlogin" },
            { 514, "Syslog/RSH" },
            { 515, "LPD/LPR" },
            { 520, "RIP" },
            { 521, "RIPng" },
            { 540, "UUCP" },
            { 543, "KLogin" },
            { 544, "KShell" },
            { 546, "DHCPv6-Client" },
            { 547, "DHCPv6-Server" },
            { 548, "AFP" },
            { 554, "RTSP" },
            { 563, "NNTPS" },
            { 587, "SMTP-Submission" },
            { 593, "MS-RPC-HTTPS" },
            { 623, "IPMI" },
            { 631, "IPP/CUPS" },
            { 636, "LDAPS" },
            { 639, "MSDP" },
            { 646, "LDP" },
            { 691, "MS-Exchange" },
            { 749, "Kerberos-Admin" },
            { 750, "Kerberos-IV" },
            { 830, "NETCONF-SSH" },
            { 873, "Rsync" },
            { 902, "VMware-Auth" },
            { 903, "VMware-Console" },
            { 993, "IMAPS" },
            { 995, "POP3S" },
            { 1024, "Reserved" },
            { 1025, "Network-Blackjack" },
            { 1026, "Calendar-Access" },
            { 1027, "ICQ" },
            { 1028, "MS-DCOM" },
            { 1029, "MS-DCOM2" },
            { 1080, "SOCKS" },
            { 1099, "RMI" },
            { 1194, "OpenVPN" },
            { 1234, "VLC" },
            { 1270, "Microsoft-MOM" },
            { 1293, "IPSec-NAT-T" },
            { 1344, "ICAP" },
            { 1352, "Lotus-Notes" },
            { 1414, "IBM-MQSeries" },
            { 1433, "MSSQL" },
            { 1434, "MSSQL-Monitor" },
            { 1494, "Citrix-ICA" },
            { 1512, "WINS" },
            { 1521, "Oracle" },
            { 1522, "Oracle-TNS" },
            { 1526, "Oracle-Auto-Data-Warehouse" },
            { 1527, "Oracle-Connection-Manager" },
            { 1529, "Oracle-Admin" },
            { 1630, "Oracle-Web-Cache" },
            { 1701, "L2TP" },
            { 1720, "H.323" },
            { 1723, "PPTP" },
            { 1755, "Windows-Media" },
            { 1761, "Novell-ZEN" },
            { 1812, "RADIUS-Auth" },
            { 1813, "RADIUS-Acct" },
            { 1863, "MSN-Messenger" },
            { 1883, "MQTT" },
            { 1900, "UPnP/SSDP" },
            { 1935, "RTMP" },
            { 1984, "Big-Brother" },
            { 2000, "Cisco-SCCP" },
            { 2001, "Cisco-DC" },
            { 2049, "NFS" },
            { 2082, "CPanel" },
            { 2083, "CPanel-SSL" },
            { 2086, "WHM" },
            { 2087, "WHM-SSL" },
            { 2095, "CPanel-Webmail" },
            { 2096, "CPanel-Webmail-SSL" },
            { 2100, "Oracle-XDB" },
            { 2121, "Scientia-SSDB" },
            { 2181, "Apache-Zookeeper" },
            { 2222, "SSH-Alt" },
            { 2375, "Docker-API" },
            { 2376, "Docker-API-SSL" },
            { 2377, "Docker-Swarm" },
            { 2379, "etcd-Client" },
            { 2380, "etcd-Peer" },
            { 2382, "Postgres-Alt" },
            { 2483, "Oracle-DB" },
            { 2484, "Oracle-DB-SSL" },
            { 2638, "Sybase" },
            { 2701, "SMS-RCINFO" },
            { 2702, "SMS-XFER" },
            { 2967, "Symantec-AV" },
            { 3000, "Node.js/Ruby-on-Rails" },
            { 3001, "Nessus" },
            { 3128, "Squid-Proxy" },
            { 3268, "LDAP-GC" },
            { 3269, "LDAP-GC-SSL" },
            { 3306, "MySQL" },
            { 3389, "RDP" },
            { 3690, "Subversion" },
            { 3986, "Mapper-WS-Ethd" },
            { 4001, "Cisco-ANS" },
            { 4045, "Solaris-LockMgr" },
            { 4190, "ManageSieve" },
            { 4333, "mSQL" },
            { 4444, "Krb524" },
            { 4500, "IPSec-NAT-T" },
            { 4662, "eMule" },
            { 4672, "eMule" },
            { 4786, "Cisco-Smart-Install" },
            { 4899, "Radmin" },
            { 5000, "UPnP/Python-HTTP" },
            { 5001, "Sockets-de-Troie" },
            { 5004, "RTP" },
            { 5005, "RTP" },
            { 5009, "Airport-Admin" },
            { 5050, "Yahoo-Messenger" },
            { 5060, "SIP" },
            { 5061, "SIP-TLS" },
            { 5101, "Yahoo-Messenger" },
            { 5190, "ICQ/AIM" },
            { 5222, "XMPP-Client" },
            { 5223, "XMPP-Client-SSL" },
            { 5269, "XMPP-Server" },
            { 5280, "XMPP-HTTP" },
            { 5298, "XMPP-JID" },
            { 5353, "mDNS/Bonjour" },
            { 5432, "PostgreSQL" },
            { 5500, "VNC-HTTP" },
            { 5631, "PCAnywhere" },
            { 5632, "PCAnywhere-Data" },
            { 5800, "VNC-HTTP" },
            { 5900, "VNC" },
            { 5938, "TeamViewer" },
            { 5984, "CouchDB" },
            { 5985, "WinRM-HTTP" },
            { 5986, "WinRM-HTTPS" },
            { 6000, "X11" },
            { 6001, "X11" },
            { 6379, "Redis" },
            { 6389, "MS-Exchange-LDAP" },
            { 6443, "Kubernetes-API" },
            { 6514, "Syslog-TLS" },
            { 6543, "Mythtv" },
            { 6566, "SANE" },
            { 6667, "IRC" },
            { 6881, "BitTorrent" },
            { 6969, "BitTorrent-Tracker" },
            { 7000, "Cassandra" },
            { 7001, "Cassandra-SSL" },
            { 7070, "Real-Audio" },
            { 7474, "Neo4j-HTTP" },
            { 7473, "Neo4j-HTTPS" },
            { 7687, "Neo4j-Bolt" },
            { 8000, "HTTP-Alt" },
            { 8001, "HTTP-Alt" },
            { 8002, "HTTP-Alt" },
            { 8008, "HTTP-Alt" },
            { 8009, "HTTP-Alt" },
            { 8080, "HTTP-Alt" },
            { 8081, "HTTP-Alt" },
            { 8082, "HTTP-Alt" },
            { 8083, "HTTP-Alt" },
            { 8089, "Splunk-Web" },
            { 8090, "HTTP-Proxy" },
            { 8161, "ActiveMQ-Admin" },
            { 8181, "HTTP-Alt" },
            { 8291, "Mikrotik-Winbox" },
            { 8333, "Bitcoin" },
            { 8443, "HTTPS-Alt" },
            { 8500, "Consul" },
            { 8600, "Consul-DNS" },
            { 8728, "Mikrotik-API" },
            { 8834, "Nessus-HTTPS" },
            { 8880, "HTTP-Alt" },
            { 8888, "HTTP-Alt" },
            { 9000, "SonarQube" },
            { 9001, "Tor-ORPort" },
            { 9030, "Tor-DirPort" },
            { 9042, "Cassandra-Native" },
            { 9080, "HTTP-Alt" },
            { 9090, "Prometheus" },
            { 9100, "Node-Exporter" },
            { 9200, "Elasticsearch-HTTP" },
            { 9300, "Elasticsearch-Transport" },
            { 9418, "Git" },
            { 9443, "WSO2" },
            { 9999, "HTTP-Alt" },
            { 10000, "Webmin" },
            { 10001, "Ubiquiti-Discovery" },
            { 10080, "Amanda" },
            { 11211, "Memcached" },
            { 25565, "Minecraft" },
            { 27017, "MongoDB" },
            { 27018, "MongoDB-Shard" },
            { 27019, "MongoDB-Config" },
            { 50000, "SAP" },
            { 50070, "Hadoop-NameNode" },
            { 50075, "Hadoop-DataNode" }
        };

        public static readonly Dictionary<int, string> VulnerablePorts = new Dictionary<int, string>
        {
            { 21, "FTP - Often misconfigured, check for anonymous access" },
            { 22, "SSH - Check for weak credentials, key management" },
            { 23, "Telnet - Unencrypted, highly vulnerable" },
            { 25, "SMTP - Check for open relay configuration" },
            { 53, "DNS - Check for zone transfers, cache poisoning" },
            { 80, "HTTP - Check for web vulnerabilities" },
            { 135, "RPC - Windows RPC, often vulnerable" },
            { 139, "NetBIOS - SMB vulnerabilities, null sessions" },
            { 443, "HTTPS - Check SSL/TLS configuration" },
            { 445, "SMB - Common target for exploits" },
            { 1433, "MSSQL - Check for SQL injection, weak auth" },
            { 3306, "MySQL - Check for weak passwords, misconfig" },
            { 3389, "RDP - Brute force target, check encryption" },
            { 5432, "PostgreSQL - Check for misconfigurations" },
            { 5900, "VNC - Often unencrypted or weak passwords" }
        };

        public static string GuessOperatingSystem(int ttl)
        {
            return ttl switch
            {
                <= 64 => "Linux/Unix",
                <= 128 => "Windows",
                <= 255 => "Cisco/Network Device",
                _ => "Unknown"
            };
        }

        /// <summary>
        /// Gets the color for a port based on common classifications
        /// </summary>
        /// <param name="port">The port number</param>
        /// <returns>Color markup for the port</returns>
        public static string GetPortColor(int port)
        {
            return port switch
            {
                22 => "cyan",           // SSH
                23 => "red",            // Telnet
                25 => "green",          // SMTP
                53 => "blue",           // DNS
                80 => "yellow",         // HTTP
                110 => "green",         // POP3
                143 => "green",         // IMAP
                443 => "lime",          // HTTPS
                993 => "green",         // IMAPS
                995 => "green",         // POP3S
                3389 => "orange",       // RDP
                _ when port < 1024 => "yellow",     // Well-known ports
                _ when port < 49152 => "cyan",      // Registered ports
                _ => "white"                        // Dynamic/private ports
            };
        }

        /// <summary>
        /// Gets the color for a service based on its name
        /// </summary>
        /// <param name="service">The service name</param>
        /// <returns>Color markup for the service</returns>
        public static string GetServiceColor(string service)
        {
            if (string.IsNullOrEmpty(service))
                return "white";

            return service.ToLower() switch
            {
                "ssh" => "cyan",
                "telnet" => "red",
                "smtp" => "green",
                "dns" => "blue",
                "http" => "yellow",
                "https" => "lime",
                "ftp" => "orange",
                "pop3" => "green",
                "imap" => "green",
                "rdp" => "orange",
                _ when service.Contains("ssl") || service.Contains("tls") => "lime",
                _ when service.Contains("mail") => "green",
                _ when service.Contains("web") || service.Contains("http") => "yellow",
                _ => "white"
            };
        }

        // IPv6 related methods (stub implementations for now)
        /// <summary>
        /// Validates if the given string is a valid IPv6 address.
        /// </summary>
        /// <param name="ipv6Address">The IPv6 address to validate.</param>
        /// <returns>True if valid, false otherwise.</returns>
        public static bool IsValidIPv6(string ipv6Address)
        {
            return System.Net.IPAddress.TryParse(ipv6Address, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }

        /// <summary>
        /// Gets the scope of an IPv6 address.
        /// </summary>
        /// <param name="ipv6Address">The IPv6 address.</param>
        /// <returns>The scope description.</returns>
        public static string GetIPv6Scope(string ipv6Address)
        {
            if (System.Net.IPAddress.TryParse(ipv6Address, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (addr.IsIPv6LinkLocal) return "Link-Local";
                if (addr.IsIPv6SiteLocal) return "Site-Local";
                if (addr.IsIPv6Multicast) return "Multicast";
                return "Global";
            }
            return "Unknown";
        }

        /// <summary>
        /// Gets local IPv6 addresses.
        /// </summary>
        /// <returns>List of local IPv6 addresses.</returns>
        public static List<string> GetLocalIPv6Addresses()
        {
            var addresses = new List<string>();
            try
            {
                var networkInterfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in networkInterfaces)
                {
                    if (ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
                    {
                        foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                            {
                                addresses.Add(addr.Address.ToString());
                            }
                        }
                    }
                }
            }
            catch { }
            return addresses;
        }

        /// <summary>
        /// Checks if an IPv6 address is link-local.
        /// </summary>
        /// <param name="ipv6Address">The IPv6 address.</param>
        /// <returns>True if link-local, false otherwise.</returns>
        public static bool IsIPv6LinkLocal(string ipv6Address)
        {
            return System.Net.IPAddress.TryParse(ipv6Address, out var addr) && addr.IsIPv6LinkLocal;
        }

        /// <summary>
        /// Checks if a port is considered vulnerable.
        /// </summary>
        /// <param name="port">The port number.</param>
        /// <returns>True if the port is vulnerable, false otherwise.</returns>
        public static bool IsPortVulnerable(int port)
        {
            return VulnerablePorts.ContainsKey(port);
        }

        /// <summary>
        /// Gets vulnerability information for a port.
        /// </summary>
        /// <param name="port">The port number.</param>
        /// <returns>Vulnerability information if available, empty string otherwise.</returns>
        public static string GetPortVulnerabilityInfo(int port)
        {
            return VulnerablePorts.TryGetValue(port, out var info) ? info : string.Empty;
        }
    }
}
