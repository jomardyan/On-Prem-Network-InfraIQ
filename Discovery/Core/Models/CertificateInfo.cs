using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Discovery.Core.Models
{
    /// <summary>
    /// Contains information about an SSL/TLS certificate
    /// </summary>
    public class CertificateInfo
    {
        /// <summary>
        /// The subject name of the certificate
        /// </summary>
        public string Subject { get; set; } = "";
        
        /// <summary>
        /// The issuer name of the certificate
        /// </summary>
        public string Issuer { get; set; } = "";
        
        /// <summary>
        /// Serial number of the certificate
        /// </summary>
        public string SerialNumber { get; set; } = "";
        
        /// <summary>
        /// Date from which the certificate is valid
        /// </summary>
        public DateTime NotBefore { get; set; }
        
        /// <summary>
        /// Date until which the certificate is valid
        /// </summary>
        public DateTime ExpirationDate { get; set; }
        
        /// <summary>
        /// Indicates whether the certificate is currently valid
        /// </summary>
        public bool IsValid { get; set; }
        
        /// <summary>
        /// Validation error message if the certificate is invalid
        /// </summary>
        public string ValidationErrorMessage { get; set; } = "";
        
        /// <summary>
        /// Thumbprint of the certificate
        /// </summary>
        public string Thumbprint { get; set; } = "";
        
        /// <summary>
        /// List of domain names the certificate is valid for
        /// </summary>
        public List<string> DomainNames { get; set; } = new List<string>();
        
        /// <summary>
        /// The hashing algorithm used
        /// </summary>
        public string HashAlgorithm { get; set; } = "";
        
        /// <summary>
        /// The key algorithm used (RSA, ECC, etc.)
        /// </summary>
        public string KeyAlgorithm { get; set; } = "";
        
        /// <summary>
        /// Gets or sets the signature algorithm used for the certificate.
        /// </summary>
        public string SignatureAlgorithm { get; set; } = "";
        
        /// <summary>
        /// Key size in bits
        /// </summary>
        public int KeySize { get; set; }
        
        /// <summary>
        /// Indicates if the certificate is self-signed
        /// </summary>
        public bool IsSelfSigned { get; set; }
        
        /// <summary>
        /// Supported SSL/TLS protocol versions
        /// </summary>
        public List<string> SupportedProtocols { get; set; } = new List<string>();
        
        /// <summary>
        /// List of cipher suites supported
        /// </summary>
        public List<string> CipherSuites { get; set; } = new List<string>();
        
        /// <summary>
        /// Indicates if any weak cipher suites are supported
        /// </summary>
        public bool HasWeakCiphers { get; set; }
        
        /// <summary>
        /// Gets or sets the raw X509 certificate.
        /// </summary>
        public X509Certificate2? RawCertificate { get; set; }
        
        /// <summary>
        /// Gets or sets a list of any security issues found with the certificate.
        /// </summary>
        public List<string> SecurityIssues { get; set; } = new List<string>();
    }
}
