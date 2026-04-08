using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Constants;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Discovery.Core.Utilities;
using Discovery.Display;
using Spectre.Console;

namespace Discovery.Services.Scanning
{
    /// <summary>
    /// Advanced port scanner with multiple scanning techniques including UDP, banner grabbing, and service detection with comprehensive batch scanning capabilities
    /// </summary>
    public class AdvancedPortScanner : BaseBatchScanner, IScanner
    {
        private readonly int _timeout;
        private readonly int _maxConcurrency;

        public AdvancedPortScanner(int timeout = 1000, int maxConcurrency = 200)
        {
            _timeout = timeout;
            _maxConcurrency = maxConcurrency;
        }

        /// <summary>
        /// Performs comprehensive scan including TCP, UDP, and service detection
        /// </summary>
        public async Task<List<ScanResult>> ComprehensiveScanAsync(string ipAddress, Dictionary<int, string> tcpPorts, Dictionary<int, string> udpPorts, CancellationToken cancellationToken)
        {
            if (!IPAddress.TryParse(ipAddress, out _))
            {
                throw new ArgumentException("Invalid IP address format", nameof(ipAddress));
            }

            var results = new ConcurrentBag<ScanResult>();
            LiveScanDisplay? liveDisplay = null;
            
            // Only use interactive display when not running in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment)
            {
                liveDisplay = new LiveScanDisplay(results);
                
                AnsiConsole.MarkupLine("[bold cyan]🔍 Starting comprehensive scan with advanced techniques...[/]");
                AnsiConsole.MarkupLine($"[yellow]Target: {ipAddress}[/]");
                AnsiConsole.MarkupLine($"[yellow]TCP Ports: {tcpPorts.Count}[/]");
                AnsiConsole.MarkupLine($"[yellow]UDP Ports: {udpPorts.Count}[/]");
                AnsiConsole.WriteLine();
                
                liveDisplay.StartLiveDisplay();
            }
            
            try
            {
                // Test host connectivity first
                var pingResult = await PingHostAsync(IPAddress.Parse(ipAddress), _timeout);
                
                if (pingResult.Success)
                {
                    var os = NetworkConstants.GuessOperatingSystem(0);
                    
                    // Run TCP and UDP scans in parallel
                    var tcpTask = ScanTcpPortsWithBannerAsync(ipAddress, results, tcpPorts, pingResult.ResponseTime, os, cancellationToken);
                    var udpTask = ScanUdpPortsAsync(ipAddress, results, udpPorts, pingResult.ResponseTime, os, cancellationToken);
                    
                    await Task.WhenAll(tcpTask, udpTask);
                }
                else
                {
                    if (!TestEnvironmentDetector.IsTestEnvironment)
                    {
                        AnsiConsole.MarkupLine($"[yellow]Host {ipAddress} appears to be offline or not responding to ping.[/]");
                    }
                }
            }
            finally
            {
                if (liveDisplay != null)
                {
                    liveDisplay.StopLiveDisplay();
                    liveDisplay.Dispose();
                }
            }
            
            return results.ToList();
        }

        #region IScanner Interface Implementation

        /// <summary>
        /// Scans a single IP address for open ports (adapter for ComprehensiveScanAsync)
        /// </summary>
        public async Task<List<ScanResult>> ScanSingleIpAsync(string ipAddress, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            // Use TCP ports for the basic interface, no UDP ports for compatibility
            var udpPorts = new Dictionary<int, string>();
            return await ComprehensiveScanAsync(ipAddress, portsToScan, udpPorts, cancellationToken);
        }

        /// <summary>
        /// Scans a range of IP addresses for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanNetworkRangeAsync(string baseIp, int startRange, int endRange, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var allResults = new List<ScanResult>();
            var udpPorts = new Dictionary<int, string>();

            if (startRange > endRange || startRange < 1 || endRange > 254)
            {
                throw new ArgumentException("Invalid IP range specified");
            }

            var ipParts = baseIp.Split('.');
            if (ipParts.Length != 4)
            {
                throw new ArgumentException("Invalid base IP address format");
            }

            // Skip interactive prompts in test environment
            var totalHosts = endRange - startRange + 1;
            if (!TestEnvironmentDetector.IsTestEnvironment && totalHosts > 50)
            {
                Console.WriteLine($"About to scan {totalHosts} hosts in the range {baseIp.Substring(0, baseIp.LastIndexOf('.'))}.{startRange}-{endRange}");
                Console.Write("Continue? (y/N): ");
                var response = Console.ReadLine();
                if (!string.Equals(response?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Scan cancelled by user.");
                    return allResults;
                }
            }

            using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
            var tasks = new List<Task<List<ScanResult>>>();

            for (int i = startRange; i <= endRange; i++)
            {
                var targetIp = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.{i}";
                
                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        return await ComprehensiveScanAsync(targetIp, portsToScan, udpPorts, cancellationToken);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);
            foreach (var result in results)
            {
                allResults.AddRange(result);
            }

            return allResults;
        }

        /// <summary>
        /// Scans a CIDR network for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanCidrNetworkAsync(IPAddress networkAddress, int subnetMask, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var allResults = new List<ScanResult>();
            var udpPorts = new Dictionary<int, string>();

            if (subnetMask < 0 || subnetMask > 32)
            {
                throw new ArgumentException("Invalid subnet mask");
            }

            var hostBits = 32 - subnetMask;
            var hostCount = (int)Math.Pow(2, hostBits);
            
            // Skip network and broadcast addresses for /24 and smaller subnets
            var start = subnetMask >= 24 ? 1 : 0;
            var end = subnetMask >= 24 ? hostCount - 1 : hostCount;

            // Skip interactive prompts in test environment
            var totalHosts = end - start;
            if (!TestEnvironmentDetector.IsTestEnvironment && totalHosts > 50)
            {
                Console.WriteLine($"About to scan {totalHosts} hosts in CIDR network {networkAddress}/{subnetMask}");
                Console.Write("Continue? (y/N): ");
                var response = Console.ReadLine();
                if (!string.Equals(response?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Scan cancelled by user.");
                    return allResults;
                }
            }

            var networkBytes = networkAddress.GetAddressBytes();
            var networkLong = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0);

            using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
            var tasks = new List<Task<List<ScanResult>>>();

            for (var i = start; i < end; i++)
            {
                var hostLong = networkLong + (uint)i;
                var hostBytes = BitConverter.GetBytes(hostLong).Reverse().ToArray();
                var hostAddress = new IPAddress(hostBytes);
                var targetIp = hostAddress.ToString();

                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        return await ComprehensiveScanAsync(targetIp, portsToScan, udpPorts, cancellationToken);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);
            foreach (var result in results)
            {
                allResults.AddRange(result);
            }

            return allResults;
        }

        /// <summary>
        /// Scans a CIDR network using string notation for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanCidrNetworkAsync(string cidrNotation, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            if (!TryParseCidr(cidrNotation, out var networkAddress, out var subnetMask) || networkAddress == null)
            {
                throw new ArgumentException("Invalid CIDR notation", nameof(cidrNotation));
            }

            return await ScanCidrNetworkAsync(networkAddress, subnetMask, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans a range of public IP addresses for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanPublicIpRangeAsync(IPAddress startIp, IPAddress endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var allResults = new List<ScanResult>();
            var udpPorts = new Dictionary<int, string>();

            var startBytes = startIp.GetAddressBytes();
            var endBytes = endIp.GetAddressBytes();
            
            var startLong = BitConverter.ToUInt32(startBytes.Reverse().ToArray(), 0);
            var endLong = BitConverter.ToUInt32(endBytes.Reverse().ToArray(), 0);

            if (startLong > endLong)
            {
                throw new ArgumentException("Start IP must be less than or equal to end IP");
            }

            var totalHosts = endLong - startLong + 1;
            
            // Skip interactive prompts in test environment
            if (!TestEnvironmentDetector.IsTestEnvironment && totalHosts > 50)
            {
                Console.WriteLine($"About to scan {totalHosts} IP addresses from {startIp} to {endIp}");
                Console.Write("Continue? (y/N): ");
                var response = Console.ReadLine();
                if (!string.Equals(response?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Scan cancelled by user.");
                    return allResults;
                }
            }

            using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
            var tasks = new List<Task<List<ScanResult>>>();

            for (var i = startLong; i <= endLong; i++)
            {
                var hostBytes = BitConverter.GetBytes(i).Reverse().ToArray();
                var hostAddress = new IPAddress(hostBytes);
                var targetIp = hostAddress.ToString();

                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        return await ComprehensiveScanAsync(targetIp, portsToScan, udpPorts, cancellationToken);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);
            foreach (var result in results)
            {
                allResults.AddRange(result);
            }

            return allResults;
        }

        /// <summary>
        /// Scans a range of IP addresses using string notation for open ports
        /// </summary>
        public async Task<List<ScanResult>> ScanIpRangeAsync(string startIp, string endIp, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            if (!IPAddress.TryParse(startIp, out var startAddress))
            {
                throw new ArgumentException("Invalid start IP address", nameof(startIp));
            }

            if (!IPAddress.TryParse(endIp, out var endAddress))
            {
                throw new ArgumentException("Invalid end IP address", nameof(endIp));
            }

            return await ScanPublicIpRangeAsync(startAddress, endAddress, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans multiple targets from a CSV list containing IP addresses, CIDR networks, and IP ranges
        /// </summary>
        public async Task<List<ScanResult>> ScanCsvTargetsAsync(string csvContent, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            var targets = ParseCsvTargets(csvContent);
            return await ScanBatchTargetsAsync(targets, portsToScan, cancellationToken);
        }

        /// <summary>
        /// Scans multiple targets from a list of target strings (IPs, CIDRs, ranges)
        /// </summary>
        public async Task<List<ScanResult>> ScanBatchTargetsAsync(IEnumerable<string> targets, Dictionary<int, string> portsToScan, CancellationToken cancellationToken)
        {
            return await ProcessBatchScanAsync(targets, portsToScan, cancellationToken, ScanSingleIpAsync);
        }

        #endregion

        /// <summary>
        /// Scans TCP ports with banner grabbing and service detection
        /// </summary>
        private async Task ScanTcpPortsWithBannerAsync(string ipAddress, ConcurrentBag<ScanResult> results, Dictionary<int, string> portsToScan, long pingTime, string operatingSystem, CancellationToken token)
        {
            // Perform reverse DNS lookup once per host, not once per open port
            var hostname = await DnsLookupHelper.GetHostnameAsync(ipAddress, 2000);

            using var semaphore = new SemaphoreSlim(_maxConcurrency);
            var tasks = portsToScan.Select(async portEntry =>
            {
                await semaphore.WaitAsync(token);
                try
                {
                    if (token.IsCancellationRequested) return;

                    using var client = new TcpClient();
                    try
                    {
                        var connectTask = client.ConnectAsync(ipAddress, portEntry.Key);
                        if (await Task.WhenAny(connectTask, Task.Delay(_timeout, token)) == connectTask)
                        {
                            await connectTask;
                            
                            var serverInfo = "";
                            var banner = "";
                            var detectedService = portEntry.Value;
                            
                            // Attempt banner grabbing
                            try
                            {
                                banner = await GrabBannerAsync(client, portEntry.Key, token);
                                if (!string.IsNullOrEmpty(banner))
                                {
                                    detectedService = DetectServiceFromBanner(banner, portEntry.Key) ?? portEntry.Value;
                                    serverInfo = $"Banner: {banner.Trim()}";
                                }
                            }
                            catch
                            {
                                // Banner grabbing failed, continue with default service
                            }
                            
                            // Enhanced SSL/TLS detection for secure ports
                            if (portEntry.Key == 443 || portEntry.Key == 8443 || detectedService.Contains("SSL") || detectedService.Contains("TLS"))
                            {
                                var sslInfo = await GetEnhancedSslInfo(ipAddress, portEntry.Key);
                                if (!string.IsNullOrEmpty(sslInfo))
                                {
                                    serverInfo = string.IsNullOrEmpty(serverInfo) ? sslInfo : $"{serverInfo}; {sslInfo}";
                                }
                            }
                            
                            var isVulnerable = NetworkConstants.IsPortVulnerable(portEntry.Key);
                            var vulnInfo = isVulnerable ? NetworkConstants.GetPortVulnerabilityInfo(portEntry.Key) : "";
                            
                            var scanResult = new ScanResult(
                                IPAddress.Parse(ipAddress),
                                portEntry.Key,
                                true,
                                detectedService,
                                pingTime,
                                operatingSystem,
                                serverInfo,
                                DateTime.UtcNow,
                                "",
                                hostname,
                                isVulnerable,
                                vulnInfo,
                                detectedService
                            );
                            
                            results.Add(scanResult);
                        }
                    }
                    catch (SocketException)
                    {
                        // Port is closed
                    }
                    catch (OperationCanceledException)
                    {
                        // Scan was cancelled
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });
            
            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Scans UDP ports using various techniques
        /// </summary>
        private async Task ScanUdpPortsAsync(string ipAddress, ConcurrentBag<ScanResult> results, Dictionary<int, string> portsToScan, long pingTime, string operatingSystem, CancellationToken token)
        {
            // Perform reverse DNS lookup once per host, not once per open port
            var hostname = await DnsLookupHelper.GetHostnameAsync(ipAddress, 2000);

            using var semaphore = new SemaphoreSlim(_maxConcurrency / 2); // Use fewer concurrent UDP scans
            var tasks = portsToScan.Select(async portEntry =>
            {
                await semaphore.WaitAsync(token);
                try
                {
                    if (token.IsCancellationRequested) return;

                    var result = await ScanUdpPortAsync(ipAddress, portEntry.Key, portEntry.Value, token);
                    if (result.IsOpen)
                    {
                        var isVulnerable = NetworkConstants.IsPortVulnerable(portEntry.Key);
                        var vulnInfo = isVulnerable ? NetworkConstants.GetPortVulnerabilityInfo(portEntry.Key) : "";
                        
                        var scanResult = new ScanResult(
                            IPAddress.Parse(ipAddress),
                            portEntry.Key,
                            true,
                            $"UDP/{portEntry.Value}",
                            pingTime,
                            operatingSystem,
                            result.ServerInfo,
                            DateTime.UtcNow,
                            "",
                            hostname,
                            isVulnerable,
                            vulnInfo,
                            $"UDP/{portEntry.Value}"
                        );
                        
                        results.Add(scanResult);
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });
            
            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Scans a single UDP port with service-specific probes
        /// </summary>
        private async Task<(bool IsOpen, string ServerInfo)> ScanUdpPortAsync(string ipAddress, int port, string serviceName, CancellationToken token)
        {
            try
            {
                using var client = new UdpClient();
                client.Client.ReceiveTimeout = _timeout;
                client.Client.SendTimeout = _timeout;
                
                var endpoint = new IPEndPoint(IPAddress.Parse(ipAddress), port);
                
                // Send service-specific probe
                var probe = GetUdpProbe(port, serviceName);
                await client.SendAsync(probe, probe.Length, endpoint);
                
                // Wait for response
                try
                {
                    var receiveTask = client.ReceiveAsync();
                    var timeoutTask = Task.Delay(_timeout, token);
                    
                    var completedTask = await Task.WhenAny(receiveTask, timeoutTask);
                    if (completedTask == receiveTask)
                    {
                        var response = await receiveTask;
                        var responseData = Encoding.ASCII.GetString(response.Buffer);
                        return (true, $"UDP Response: {responseData.Trim()}");
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // ICMP port unreachable - port is closed
                    return (false, "");
                }
                catch
                {
                    // No response - could be open but filtered, or service doesn't respond to our probe
                    return (true, "UDP service detected (no response to probe)");
                }
            }
            catch
            {
                return (false, "");
            }
            
            return (false, "");
        }

        /// <summary>
        /// Gets appropriate UDP probe for the service
        /// </summary>
        private byte[] GetUdpProbe(int port, string serviceName)
        {
            // Service-specific UDP probes
            return port switch
            {
                53 => Encoding.ASCII.GetBytes("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"), // DNS query
                123 => new byte[] { 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // NTP request
                161 => Encoding.ASCII.GetBytes("\x30\x1a\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x0d\x02\x04\x00\x00\x00\x00\x02\x01\x00\x30\x00"), // SNMP get request
                69 => Encoding.ASCII.GetBytes("\x00\x01test.txt\x00netascii\x00"), // TFTP read request
                _ => Encoding.ASCII.GetBytes("Discovery probe\r\n")
            };
        }

        /// <summary>
        /// Grabs banner from TCP service
        /// </summary>
        private async Task<string> GrabBannerAsync(TcpClient client, int port, CancellationToken token)
        {
            try
            {
                var stream = client.GetStream();
                
                // Send service-specific probe
                var probe = GetTcpProbe(port);
                if (probe != null)
                {
                    await stream.WriteAsync(probe, 0, probe.Length, token);
                }
                
                // Read response
                var buffer = new byte[1024];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, token);
                
                if (bytesRead > 0)
                {
                    return Encoding.ASCII.GetString(buffer, 0, bytesRead);
                }
            }
            catch
            {
                // Banner grabbing failed
            }
            
            return "";
        }

        /// <summary>
        /// Gets appropriate TCP probe for the service
        /// </summary>
        private byte[]? GetTcpProbe(int port)
        {
            return port switch
            {
                21 => null, // FTP sends banner automatically
                22 => null, // SSH sends banner automatically
                23 => null, // Telnet sends banner automatically
                25 => null, // SMTP sends banner automatically
                80 => Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n"),
                110 => null, // POP3 sends banner automatically
                143 => null, // IMAP sends banner automatically
                443 => null, // HTTPS requires SSL handshake
                993 => null, // IMAPS requires SSL handshake
                995 => null, // POP3S requires SSL handshake
                _ => Encoding.ASCII.GetBytes("\r\n")
            };
        }

        /// <summary>
        /// Detects service from banner content
        /// </summary>
        private string? DetectServiceFromBanner(string banner, int port)
        {
            var lowerBanner = banner.ToLowerInvariant();
            
            // HTTP servers
            if (lowerBanner.Contains("http/") || lowerBanner.Contains("server:"))
            {
                if (lowerBanner.Contains("apache")) return "Apache HTTP Server";
                if (lowerBanner.Contains("nginx")) return "Nginx HTTP Server";
                if (lowerBanner.Contains("iis")) return "Microsoft IIS";
                if (lowerBanner.Contains("lighttpd")) return "Lighttpd";
                return "HTTP Server";
            }
            
            // SSH servers
            if (lowerBanner.Contains("ssh-"))
            {
                if (lowerBanner.Contains("openssh")) return "OpenSSH";
                if (lowerBanner.Contains("dropbear")) return "Dropbear SSH";
                return "SSH Server";
            }
            
            // FTP servers
            if (lowerBanner.Contains("ftp"))
            {
                if (lowerBanner.Contains("vsftpd")) return "Very Secure FTP Daemon";
                if (lowerBanner.Contains("proftpd")) return "ProFTPD";
                if (lowerBanner.Contains("pureftpd")) return "Pure-FTPd";
                return "FTP Server";
            }
            
            // Mail servers
            if (lowerBanner.Contains("smtp") || lowerBanner.Contains("mail"))
            {
                if (lowerBanner.Contains("postfix")) return "Postfix SMTP";
                if (lowerBanner.Contains("sendmail")) return "Sendmail";
                if (lowerBanner.Contains("exim")) return "Exim";
                return "Mail Server";
            }
            
            // Database servers
            if (lowerBanner.Contains("mysql")) return "MySQL Database";
            if (lowerBanner.Contains("postgresql")) return "PostgreSQL Database";
            if (lowerBanner.Contains("mongodb")) return "MongoDB Database";
            if (lowerBanner.Contains("redis")) return "Redis Database";
            
            return null;
        }

        /// <summary>
        /// Gets enhanced SSL/TLS certificate information
        /// </summary>
        private async Task<string> GetEnhancedSslInfo(string ipAddress, int port)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);
                if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
                {
                    return "SSL connection timed out";
                }
                
                await connectTask;
                
                using var sslStream = new System.Net.Security.SslStream(client.GetStream(), false, ValidateServerCertificate, null);
                try
                {
                    await sslStream.AuthenticateAsClientAsync(ipAddress);
                    
                    var protocol = sslStream.SslProtocol.ToString();
                    var cipher = sslStream.CipherAlgorithm.ToString();
                    var strength = sslStream.CipherStrength;
                    
                    if (sslStream.RemoteCertificate is System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
                    {
                        var subject = cert.Subject;
                        var issuer = cert.Issuer;
                        var expiry = cert.NotAfter;
                        var keySize = GetKeySize(cert.PublicKey);
                        
                        var isExpired = DateTime.Now > expiry;
                        var expiryWarning = isExpired ? " [EXPIRED]" : "";
                        
                        return $"SSL: {protocol}, Cipher: {cipher}/{strength}bit, Cert: {subject}, Key: {keySize}bit, Expires: {expiry:yyyy-MM-dd}{expiryWarning}";
                    }
                    
                    return $"SSL: {protocol}, Cipher: {cipher}/{strength}bit";
                }
                catch (Exception ex)
                {
                    return $"SSL Error: {ex.Message}";
                }
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// SSL certificate validation callback
        /// </summary>
        private static int GetKeySize(System.Security.Cryptography.X509Certificates.PublicKey publicKey)
        {
            try
            {
                // Try RSA first
                using var rsa = publicKey.GetRSAPublicKey();
                if (rsa != null)
                    return rsa.KeySize;
            }
            catch
            {
                // Not RSA, try other algorithms
            }

            try
            {
                // Try ECDsa
                using var ecdsa = publicKey.GetECDsaPublicKey();
                if (ecdsa != null)
                    return ecdsa.KeySize;
            }
            catch
            {
                // Not ECDsa
            }

            try
            {
                // Try DSA (deprecated but still might be used)
                using var dsa = publicKey.GetDSAPublicKey();
                if (dsa != null)
                    return dsa.KeySize;
            }
            catch
            {
                // Not DSA
            }

            // Fallback to 0 if we can't determine the key size
            return 0;
        }

        private bool ValidateServerCertificate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate? certificate, System.Security.Cryptography.X509Certificates.X509Chain? chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            // Accept all certificates for scanning purposes
            return true;
        }

        /// <summary>
        /// Cross-platform connectivity test using TCP connection to common ports
        /// </summary>
        private async Task<(bool Success, long ResponseTime)> PingHostAsync(IPAddress ipAddress, int timeout)
        {
            try
            {
                var commonPorts = new[] { 80, 443, 22, 21, 23, 25, 53, 110, 995, 993, 143, 3389 };
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                // ToList() is required because tasks are removed from the list during the loop.
                // The hardcoded commonPorts array is small (12 entries) so all tasks are created upfront.
                var tasks = commonPorts.Select(port => TestTcpConnection(ipAddress, port, timeout / commonPorts.Length)).ToList();
                
                try
                {
                    // Keep checking as tasks complete; return as soon as one succeeds
                    while (tasks.Count > 0)
                    {
                        var completedTask = await Task.WhenAny(tasks);
                        tasks.Remove(completedTask);

                        if (await completedTask)
                        {
                            stopwatch.Stop();
                            return (true, stopwatch.ElapsedMilliseconds);
                        }
                    }
                }
                catch
                {
                    // All connections failed
                }
                finally
                {
                    stopwatch.Stop();
                }
                
                return (false, 0);
            }
            catch
            {
                return (false, 0);
            }
        }

        /// <summary>
        /// Tests TCP connection to a specific port
        /// </summary>
        private async Task<bool> TestTcpConnection(IPAddress ipAddress, int port, int timeout)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);
                if (await Task.WhenAny(connectTask, Task.Delay(timeout)) == connectTask)
                {
                    return client.Connected;
                }
            }
            catch
            {
                // Connection failed
            }
            return false;
        }
    }
}