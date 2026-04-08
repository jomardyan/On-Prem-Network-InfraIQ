using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Spectre.Console;

// Use our specific CertificateInfo to avoid ambiguity
using CertInfo = Discovery.Core.Models.CertificateInfo;

namespace Discovery.Services.Security
{
    /// <summary>
    /// Provides SSL/TLS certificate checking functionality
    /// </summary>
    public class SslCertificateChecker
    {
        private readonly HttpClient _httpClient;
        private readonly int _timeout;

        public SslCertificateChecker(int timeout = 5000)
        {
            _timeout = timeout;
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromMilliseconds(_timeout)
            };
        }

        /// <summary>
        /// Checks SSL/TLS certificate for a given host
        /// </summary>
        /// <param name="host">The hostname or IP address to check</param>
        /// <param name="port">The port to check (usually 443)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Certificate information</returns>
        public async Task<CertInfo> CheckCertificateAsync(string host, int port = 443, CancellationToken cancellationToken = default)
        {
            var certInfo = new CertInfo();
            
            try
            {
                // Check if host is IP address - if so we need to use it directly
                bool isIpAddress = IPAddress.TryParse(host, out _);
                var targetHost = isIpAddress ? host : host.Replace("https://", "").Replace("http://", "").Split('/')[0];

                using var tcpClient = new TcpClient();
                var connectTask = tcpClient.ConnectAsync(targetHost, port);
                if (await Task.WhenAny(connectTask, Task.Delay(_timeout, cancellationToken)) != connectTask)
                {
                    throw new TimeoutException($"Connection to {targetHost}:{port} timed out.");
                }
                
                await connectTask;
                
                using var sslStream = new System.Net.Security.SslStream(
                    tcpClient.GetStream(), 
                    false, 
                    (sender, certificate, chain, sslPolicyErrors) => true);
                
                // For IP addresses, we need to use a custom SslClientAuthenticationOptions to avoid validation errors
                if (isIpAddress)
                {
                    var options = new System.Net.Security.SslClientAuthenticationOptions
                    {
                        TargetHost = targetHost,
                        RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true,
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.None
                    };
                    
                    await sslStream.AuthenticateAsClientAsync(options, cancellationToken);
                }
                else
                {
                    await sslStream.AuthenticateAsClientAsync(
                        targetHost, 
                        null, 
                        System.Security.Authentication.SslProtocols.None, 
                        false);
                }
                
                X509Certificate2 certificate;
                if (sslStream.RemoteCertificate is X509Certificate2 cert)
                {
                    certificate = cert;
                }
                else
                {
                    if (sslStream.RemoteCertificate != null)
                    {
                        certificate = new X509Certificate2(sslStream.RemoteCertificate);
                    }
                    else
                    {
                        throw new InvalidOperationException("No certificate was provided by the remote server.");
                    }
                }

                // Extract certificate information
                certInfo.Subject = certificate.Subject;
                certInfo.Issuer = certificate.Issuer;
                certInfo.NotBefore = certificate.NotBefore;
                certInfo.ExpirationDate = certificate.NotAfter;
                certInfo.Thumbprint = certificate.Thumbprint;
                certInfo.SerialNumber = certificate.SerialNumber;
                certInfo.HashAlgorithm = certificate.SignatureAlgorithm?.FriendlyName ?? "Unknown";
                
                // Check validity
                certInfo.IsValid = certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now;
                
                // Check if self-signed
                certInfo.IsSelfSigned = certificate.Subject == certificate.Issuer;

                // Check for security issues
                CheckForSecurityIssues(certInfo, certificate);
            }
            catch (Exception ex)
            {
                certInfo.SecurityIssues.Add($"Error checking certificate: {ex.Message}");
                certInfo.IsValid = false;
            }
            
            return certInfo;
        }

        /// <summary>
        /// Checks if a certificate is trusted (has a valid certificate chain)
        /// </summary>
        /// <param name="host">The host to check</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if certificate is trusted, false otherwise</returns>
        public async Task<bool> IsCertificateTrustedAsync(string host, CancellationToken cancellationToken = default)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}");
                var response = await _httpClient.SendAsync(request, cancellationToken);
                return true;
            }
            catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Performs comprehensive SSL/TLS security audit
        /// </summary>
        public async Task<SecurityAuditResult> PerformSslAuditAsync(string host, CancellationToken cancellationToken = default)
        {
            AnsiConsole.MarkupLine($"[cyan]Analyzing SSL/TLS security for [bold]{host}[/]...[/]");
            
            var result = new SecurityAuditResult
            {
                Target = host
            };
            
            var certInfo = await CheckCertificateAsync(host, 443, cancellationToken);
            result.CertificateInfo = certInfo;
            
            int securityScore = 100;
            
            // Deduct points for security issues
            securityScore -= certInfo.SecurityIssues.Count * 10;
            
            // Check if certificate is expired
            if (!certInfo.IsValid)
            {
                result.Vulnerabilities.Add(new VulnerabilityInfo
                {
                    Name = "Invalid SSL/TLS Certificate",
                    Description = "The SSL/TLS certificate is not valid. It may be expired or not yet valid.",
                    Severity = VulnerabilitySeverity.High,
                    Remediation = "Replace with a valid certificate from a trusted certificate authority."
                });
                securityScore -= 30;
            }
            
            // Check if certificate is self-signed
            if (certInfo.IsSelfSigned)
            {
                result.Vulnerabilities.Add(new VulnerabilityInfo
                {
                    Name = "Self-signed Certificate",
                    Description = "The server is using a self-signed certificate which is not trusted by default.",
                    Severity = VulnerabilitySeverity.Medium,
                    Remediation = "Replace with a certificate from a trusted certificate authority."
                });
                securityScore -= 20;
            }
            
            // Check expiration date
            if (certInfo.ExpirationDate < DateTime.Now.AddMonths(1))
            {
                result.Vulnerabilities.Add(new VulnerabilityInfo
                {
                    Name = "Certificate Expiring Soon",
                    Description = $"The certificate will expire on {certInfo.ExpirationDate.ToShortDateString()}.",
                    Severity = VulnerabilitySeverity.Medium,
                    Remediation = "Renew the certificate before it expires."
                });
                securityScore -= 15;
            }
            
            // Weak signature algorithm
            if (certInfo.HashAlgorithm?.Contains("SHA1") == true ||
                certInfo.HashAlgorithm?.Contains("MD5") == true)
            {
                result.Vulnerabilities.Add(new VulnerabilityInfo
                {
                    Name = "Weak Signature Algorithm",
                    Description = $"The certificate uses a weak signature algorithm: {certInfo.SignatureAlgorithm}",
                    Severity = VulnerabilitySeverity.High,
                    Remediation = "Replace with a certificate using a stronger algorithm like SHA-256."
                });
                securityScore -= 25;
            }
            
            // Normalize score
            result.SecurityScore = Math.Max(0, Math.Min(100, securityScore));
            
            // Create a summary
            result.Summary = $"SSL/TLS security audit for {host} completed with a score of {result.SecurityScore}/100.";
            if (result.Vulnerabilities.Count > 0)
            {
                result.Summary += $" Found {result.Vulnerabilities.Count} security issue(s).";
            }
            
            return result;
        }
        
        /// <summary>
        /// Checks for common security issues in certificates
        /// </summary>
        private void CheckForSecurityIssues(CertificateInfo certInfo, X509Certificate2 certificate)
        {
            // Check for expired certificate
            if (certificate.NotAfter < DateTime.Now)
            {
                certInfo.SecurityIssues.Add($"Certificate expired on {certificate.NotAfter.ToShortDateString()}");
            }
            
            // Check for not-yet-valid certificate
            if (certificate.NotBefore > DateTime.Now)
            {
                certInfo.SecurityIssues.Add($"Certificate not valid until {certificate.NotBefore.ToShortDateString()}");
            }
            
            // Check for self-signed certificate
            if (certificate.Subject == certificate.Issuer)
            {
                certInfo.SecurityIssues.Add("Certificate is self-signed");
            }
            
            // Check for weak signature algorithm
            if (certificate.SignatureAlgorithm.FriendlyName?.Contains("SHA1") == true || 
                certificate.SignatureAlgorithm.FriendlyName?.Contains("MD5") == true)
            {
                certInfo.SecurityIssues.Add($"Weak signature algorithm: {certificate.SignatureAlgorithm.FriendlyName}");
            }
            
            // Check for short key length
            try
            {
                // RSA check
                if (certificate.PublicKey.Oid.FriendlyName?.Contains("RSA") == true)
                {
                    using var rsaKey = certificate.PublicKey.GetRSAPublicKey();
                    if (rsaKey != null && rsaKey.KeySize < 2048)
                    {
                        certInfo.SecurityIssues.Add($"Weak RSA key length: {rsaKey.KeySize} bits (should be at least 2048 bits)");
                    }
                }
                // DSA check
                else if (certificate.PublicKey.Oid.FriendlyName?.Contains("DSA") == true)
                {
                    using var dsaKey = certificate.PublicKey.GetDSAPublicKey();
                    if (dsaKey != null && dsaKey.KeySize < 2048)
                    {
                        certInfo.SecurityIssues.Add($"Weak DSA key length: {dsaKey.KeySize} bits (should be at least 2048 bits)");
                    }
                }
            }
            catch
            {
                // Ignore key length check errors
            }
            
            // Check if about to expire
            if (certificate.NotAfter < DateTime.Now.AddDays(30))
            {
                certInfo.SecurityIssues.Add($"Certificate expires soon: {certificate.NotAfter.ToShortDateString()}");
            }
        }
    }
}
