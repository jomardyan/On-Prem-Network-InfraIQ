using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Spectre.Console;

namespace Discovery.Security
{
    /// <summary>
    /// Advanced honeypot and security trap detection system with multiple detection algorithms
    /// </summary>
    public static class HoneypotDetector
    {
        private static readonly Dictionary<string, int> SuspiciousPatterns = new()
        {
            { "excessive_open_ports", 25 },
            { "unusual_service_combo", 20 },
            { "fake_banners", 15 },
            { "timing_anomaly", 10 },
            { "behavior_inconsistency", 15 },
            { "honeypot_signatures", 30 },
            { "artificial_responses", 20 },
            { "network_topology_anomaly", 15 }
        };

        private static readonly Dictionary<string, string[]> KnownHoneypotSignatures = new()
        {
            ["Kippo"] = new[] { "SSH-2.0-OpenSSH_5.1p1", "SSH-2.0-OpenSSH_6.0p1", "last login:" },
            ["Cowrie"] = new[] { "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", "cowrie" },
            ["Dionaea"] = new[] { "Microsoft-IIS/6.0", "dionaea" },
            ["Glastopf"] = new[] { "Apache/2.2.22", "glastopf" },
            ["Conpot"] = new[] { "Siemens, SIMATIC", "conpot" },
            ["Elastichoney"] = new[] { "elasticsearch", "elastic_honey" },
            ["MongoDB-HoneyProxy"] = new[] { "MongoDB", "ismaster" },
            ["MySQL-Honeypot"] = new[] { "5.5.43-0ubuntu0", "mysql_native_password" },
            ["RDP-Honeypot"] = new[] { "Microsoft Terminal Services", "mstshash" },
            ["VNC-Honeypot"] = new[] { "RFB 003.008", "VNC" },
            ["Telnet-Honeypot"] = new[] { "Welcome to", "login:" },
            ["Generic-Honeypot"] = new[] { "honeypot", "honey", "trap", "canary", "decoy" }
        };

        /// <summary>
        /// Analyzes scan results to detect potential honeypots
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="scanResults">Collection of scan results</param>
        /// <returns>Honeypot analysis result</returns>
        public static HoneypotAnalysisResult AnalyzePotentialHoneypot(
            IPAddress target, 
            IEnumerable<ScanResult> scanResults)
        {
            var results = scanResults.ToList();
            var suspicionScore = 0;
            var indicators = new List<string>();

            // Check for excessive open ports
            var openPorts = results.Where(r => r.IsOpen).Count();
            if (openPorts > 30)
            {
                suspicionScore += SuspiciousPatterns["excessive_open_ports"];
                indicators.Add($"Excessive open ports detected: {openPorts}");
            }

            // Check for unusual service combinations
            var services = results.Where(r => r.IsOpen)
                                .Select(r => r.Service.ToLowerInvariant())
                                .ToList();

            // Honeypots often run many different services
            if (services.Contains("http") && services.Contains("ftp") && 
                services.Contains("ssh") && services.Contains("telnet"))
            {
                suspicionScore += SuspiciousPatterns["unusual_service_combo"];
                indicators.Add("Suspicious service combination: HTTP+FTP+SSH+Telnet");
            }
            
            // Additional suspicious combinations
            if (services.Contains("ftp") && services.Contains("telnet") && services.Contains("smtp"))
            {
                suspicionScore += SuspiciousPatterns["unusual_service_combo"];
                indicators.Add("Suspicious service combination: FTP+Telnet+SMTP");
            }

            // Check for known honeypot signatures
            foreach (var result in results.Where(r => r.IsOpen))
            {
                foreach (var honeypot in KnownHoneypotSignatures)
                {
                    if (honeypot.Value.Any(signature => 
                        result.Service.Contains(signature, StringComparison.OrdinalIgnoreCase) ||
                        result.ServerInfo.Contains(signature, StringComparison.OrdinalIgnoreCase)))
                    {
                        suspicionScore += SuspiciousPatterns["honeypot_signatures"];
                        indicators.Add($"Known honeypot signature detected: {honeypot.Key} on port {result.Port}");
                        break;
                    }
                }
            }

            // Check response timing patterns
            var avgResponseTime = results.Where(r => r.IsOpen && r.PingTime > 0)
                                        .Select(r => r.PingTime)
                                        .DefaultIfEmpty(0)
                                        .Average();

            if (avgResponseTime > 0 && avgResponseTime < 5) // Suspiciously fast
            {
                suspicionScore += SuspiciousPatterns["timing_anomaly"];
                indicators.Add($"Suspiciously fast response times: {avgResponseTime:F2}ms average");
            }

            // Check for artificial consistency
            var responseTimes = results.Where(r => r.IsOpen && r.PingTime > 0)
                                     .Select(r => r.PingTime)
                                     .ToList();

            if (responseTimes.Count > 3 && responseTimes.All(t => t == responseTimes.First()))
            {
                suspicionScore += SuspiciousPatterns["artificial_responses"];
                indicators.Add("Artificially consistent response times detected");
            }

            // Determine threat level
            var threatLevel = suspicionScore switch
            {
                >= 60 => ThreatLevel.High,
                >= 30 => ThreatLevel.Medium,
                >= 15 => ThreatLevel.Low,
                _ => ThreatLevel.None
            };

            // Generate recommendations based on threat level
            var recommendations = new List<string>();
            switch (threatLevel)
            {
                case ThreatLevel.High:
                    recommendations.Add("⚠️ IMMEDIATE ACTION REQUIRED: This target is highly likely to be a honeypot");
                    recommendations.Add("🚫 STOP all scanning activities immediately");
                    recommendations.Add("🔍 Investigate how this IP was discovered to avoid future encounters");
                    recommendations.Add("📝 Document this IP for future reference and avoidance");
                    break;
                case ThreatLevel.Medium:
                    recommendations.Add("⚠️ CAUTION: This target shows suspicious honeypot characteristics");
                    recommendations.Add("🛑 Consider stopping scan or proceeding with extreme caution");
                    recommendations.Add("📊 Use minimal scanning techniques if proceeding");
                    recommendations.Add("👀 Monitor for unusual network behavior");
                    break;
                case ThreatLevel.Low:
                    recommendations.Add("ℹ️ Minor honeypot indicators detected");
                    recommendations.Add("🔍 Proceed with caution and additional verification");
                    recommendations.Add("📝 Monitor scan results for unusual patterns");
                    break;
                case ThreatLevel.None:
                    recommendations.Add("✅ No significant honeypot indicators detected");
                    recommendations.Add("🚀 Target appears safe for normal scanning");
                    break;
            }

            return new HoneypotAnalysisResult
            {
                Target = target.ToString(),
                SuspicionScore = Math.Min(suspicionScore, 100),
                ThreatLevel = threatLevel,
                Indicators = indicators,
                Recommendations = recommendations
            };
        }

        /// <summary>
        /// Quick honeypot likelihood check for single port
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="port">Port to check</param>
        /// <returns>True if port shows honeypot characteristics</returns>
        public static async Task<bool> IsLikelyHoneypotAsync(IPAddress target, int port)
        {
            try
            {
                // Quick checks for obvious honeypot indicators
                var banner = await GetServiceBannerAsync(target, port);
                
                // Check for known honeypot signatures in banner
                foreach (var honeypot in KnownHoneypotSignatures)
                {
                    if (honeypot.Value.Any(signature => 
                        banner.Contains(signature, StringComparison.OrdinalIgnoreCase)))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Retrieves service banner from a specific port
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="port">Port to scan</param>
        /// <returns>Service banner or empty string</returns>
        private static async Task<string> GetServiceBannerAsync(IPAddress target, int port)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(target, port);
                var timeoutTask = Task.Delay(2000);
                
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                if (completedTask != connectTask || !client.Connected)
                    return "";

                using var stream = client.GetStream();
                var buffer = new byte[512];
                
                stream.ReadTimeout = 1000;
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
        /// Checks if a target might be a canary or monitoring system
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="scanResults">Collection of scan results</param>
        /// <returns>True if likely canary system</returns>
        public static bool IsLikelyCanarySystem(IPAddress target, IEnumerable<ScanResult> scanResults)
        {
            var results = scanResults.ToList();
            var openPorts = results.Where(r => r.IsOpen).Select(r => r.Port).ToList();

            // Canary systems often have limited, specific ports open
            if (openPorts.Count >= 1 && openPorts.Count <= 5)
            {
                // Common canary port combinations
                var canaryPatterns = new[]
                {
                    new[] { 22 }, // SSH only
                    new[] { 80, 443 }, // Web only
                    new[] { 21, 22 }, // FTP + SSH
                    new[] { 23, 80 }, // Telnet + HTTP
                    new[] { 1433 }, // MSSQL only
                    new[] { 3306 }, // MySQL only
                };

                foreach (var pattern in canaryPatterns)
                {
                    if (pattern.All(p => openPorts.Contains(p)) && openPorts.Count == pattern.Length)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Performs comprehensive honeypot analysis with network behavior checks
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="timeout">Operation timeout in milliseconds</param>
        /// <returns>True if likely honeypot</returns>
        public static async Task<bool> PerformAdvancedHoneypotAnalysisAsync(IPAddress target, int timeout = 5000)
        {
            try
            {
                // Perform multiple ping tests to analyze response patterns
                using var ping = new Ping();
                var responseTimes = new List<long>();
                
                for (int i = 0; i < 5; i++)
                {
                    var reply = await ping.SendPingAsync(target, timeout / 5);
                    if (reply.Status == IPStatus.Success)
                    {
                        responseTimes.Add(reply.RoundtripTime);
                        
                        // Check for unusual TTL values
                        if (reply.Options?.Ttl is int ttl && ttl < 30)
                        {
                            return true; // Unusual TTL might indicate honeypot
                        }
                    }
                    
                    await Task.Delay(200); // Delay between pings
                }

                // Analyze response time patterns
                if (responseTimes.Count >= 3)
                {
                    var variance = CalculateVariance(responseTimes);
                    if (variance < 2.0) // Too consistent responses
                    {
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false; // Assume not honeypot on error
            }
        }

        /// <summary>
        /// Calculates variance of response times
        /// </summary>
        /// <param name="values">List of response times</param>
        /// <returns>Variance value</returns>
        private static double CalculateVariance(List<long> values)
        {
            if (values.Count < 2) return 0;
            
            var mean = values.Average();
            var sumOfSquares = values.Sum(v => Math.Pow(v - mean, 2));
            return sumOfSquares / (values.Count - 1);
        }
    }

    /// <summary>
    /// Result of honeypot analysis
    /// </summary>
    public class HoneypotAnalysisResult
    {
        /// <summary>
        /// Target IP address that was analyzed
        /// </summary>
        public string Target { get; set; } = "";

        /// <summary>
        /// Suspicion score (0-100, higher = more likely honeypot)
        /// </summary>
        public int SuspicionScore { get; set; }

        /// <summary>
        /// Threat level assessment
        /// </summary>
        public ThreatLevel ThreatLevel { get; set; }

        /// <summary>
        /// List of honeypot indicators found
        /// </summary>
        public List<string> Indicators { get; set; } = new List<string>();

        /// <summary>
        /// List of recommendations based on analysis
        /// </summary>
        public List<string> Recommendations { get; set; } = new List<string>();
    }

    /// <summary>
    /// Threat level enumeration
    /// </summary>
    public enum ThreatLevel
    {
        /// <summary>
        /// No threat detected
        /// </summary>
        None = 0,

        /// <summary>
        /// Low threat level
        /// </summary>
        Low = 1,

        /// <summary>
        /// Medium threat level
        /// </summary>
        Medium = 2,

        /// <summary>
        /// High threat level - likely honeypot
        /// </summary>
        High = 3
    }
}