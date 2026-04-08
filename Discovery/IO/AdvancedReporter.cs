using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Discovery.Security;
using Spectre.Console;

namespace Discovery.IO
{
    /// <summary>
    /// Advanced reporting system with multiple output formats including PDF, HTML, and risk assessment
    /// </summary>
    public class AdvancedReporter
    {
        /// <summary>
        /// Generates a comprehensive security assessment report
        /// </summary>
        /// <param name="assessmentData">Security assessment data containing scan results and vulnerabilities</param>
        /// <param name="reportType">Type of report to generate</param>
        /// <param name="outputPath">Output file path</param>
        /// <returns>Path to generated report</returns>
        public async Task<string> GenerateSecurityReportAsync(
            SecurityAssessmentData assessmentData,
            ReportType reportType,
            string outputPath)
        {
            var timestamp = DateTime.Now;
            var reportGenerator = reportType switch
            {
                ReportType.Html => (IReportGenerator)new HtmlReportGenerator(),
                ReportType.Pdf => new PdfReportGenerator(),
                ReportType.Json => new JsonReportGenerator(),
                ReportType.Csv => new CsvReportGenerator(),
                ReportType.Executive => new ExecutiveReportGenerator(),
                _ => throw new ArgumentException("Unsupported report type")
            };

            AnsiConsole.MarkupLine($"[bold cyan]📄 Generating {reportType} security report...[/]");
            
            var reportContent = await reportGenerator.GenerateReportAsync(assessmentData);
            var finalPath = Path.ChangeExtension(outputPath, reportGenerator.FileExtension);
            
            await File.WriteAllTextAsync(finalPath, reportContent);
            
            AnsiConsole.MarkupLine($"[green]✅ Report generated: {finalPath}[/]");
            return finalPath;
        }

        /// <summary>
        /// Calculates risk scores for discovered vulnerabilities
        /// </summary>
        /// <param name="vulnerabilities">Collection of vulnerabilities</param>
        /// <returns>Risk assessment results</returns>
        public RiskAssessment CalculateRiskScores(IEnumerable<object> vulnerabilities)
        {
            var assessment = new RiskAssessment();
            var vulnList = vulnerabilities.ToList();

            // Calculate severity distribution
            var severityCounts = new Dictionary<string, int>
            {
                ["Critical"] = 0,
                ["High"] = 0,
                ["Medium"] = 0,
                ["Low"] = 0,
                ["Info"] = 0
            };

            foreach (var vuln in vulnList)
            {
                var severity = GetVulnerabilitySeverity(vuln);
                if (severityCounts.ContainsKey(severity))
                {
                    severityCounts[severity]++;
                }
            }

            assessment.SeverityDistribution = severityCounts;

            // Calculate overall risk score (0-100)
            var riskScore = CalculateOverallRiskScore(severityCounts);
            assessment.OverallRiskScore = riskScore;
            assessment.RiskLevel = GetRiskLevel(riskScore);

            // Generate recommendations
            assessment.Recommendations = GenerateRecommendations(severityCounts, vulnList);

            // Calculate compliance scores
            assessment.ComplianceScores = CalculateComplianceScores(vulnList);

            return assessment;
        }

        /// <summary>
        /// Generates an executive summary report
        /// </summary>
        /// <param name="assessmentData">Security assessment data</param>
        /// <returns>Executive summary content</returns>
        public async Task<string> GenerateExecutiveSummaryAsync(SecurityAssessmentData assessmentData)
        {
            var summary = new StringBuilder();
            var riskAssessment = CalculateRiskScores(assessmentData.AllVulnerabilities);

            summary.AppendLine("# Executive Security Assessment Summary");
            summary.AppendLine($"**Assessment Date:** {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            summary.AppendLine($"**Scope:** {assessmentData.ScanScope}");
            summary.AppendLine();

            // Key findings
            summary.AppendLine("## Key Findings");
            summary.AppendLine($"- **Overall Risk Level:** {riskAssessment.RiskLevel}");
            summary.AppendLine($"- **Risk Score:** {riskAssessment.OverallRiskScore}/100");
            summary.AppendLine($"- **Critical Vulnerabilities:** {riskAssessment.SeverityDistribution["Critical"]}");
            summary.AppendLine($"- **High Vulnerabilities:** {riskAssessment.SeverityDistribution["High"]}");
            summary.AppendLine($"- **Total Hosts Scanned:** {assessmentData.HostsScanned}");
            summary.AppendLine($"- **Active Hosts Found:** {assessmentData.ActiveHosts}");
            summary.AppendLine();

            // Risk breakdown
            summary.AppendLine("## Risk Breakdown");
            foreach (var severity in riskAssessment.SeverityDistribution)
            {
                if (severity.Value > 0)
                {
                    summary.AppendLine($"- **{severity.Key}:** {severity.Value} issues");
                }
            }
            summary.AppendLine();

            // Top recommendations
            summary.AppendLine("## Priority Recommendations");
            foreach (var recommendation in riskAssessment.Recommendations.Take(5))
            {
                summary.AppendLine($"- {recommendation}");
            }
            summary.AppendLine();

            // Compliance status
            summary.AppendLine("## Compliance Assessment");
            foreach (var compliance in riskAssessment.ComplianceScores)
            {
                var status = compliance.Value >= 80 ? "✅ Compliant" : "❌ Non-Compliant";
                summary.AppendLine($"- **{compliance.Key}:** {compliance.Value}% {status}");
            }

            return await Task.FromResult(summary.ToString());
        }

        private string GetVulnerabilitySeverity(object vulnerability)
        {
            // Extract severity from different vulnerability types
            return vulnerability switch
            {
                CredentialVulnerability cv => cv.Severity,
                WebVulnerability wv => wv.Severity,
                { } v when v.GetType().GetProperty("Severity")?.GetValue(v) is string severity => severity,
                _ => "Info"
            };
        }

        private int CalculateOverallRiskScore(Dictionary<string, int> severityCounts)
        {
            // Weighted scoring system
            var score = severityCounts["Critical"] * 25 +
                       severityCounts["High"] * 15 +
                       severityCounts["Medium"] * 8 +
                       severityCounts["Low"] * 3 +
                       severityCounts["Info"] * 1;

            return Math.Min(100, score); // Cap at 100
        }

        private string GetRiskLevel(int riskScore)
        {
            return riskScore switch
            {
                >= 80 => "Critical",
                >= 60 => "High",
                >= 40 => "Medium",
                >= 20 => "Low",
                _ => "Minimal"
            };
        }

        private List<string> GenerateRecommendations(Dictionary<string, int> severityCounts, List<object> vulnerabilities)
        {
            var recommendations = new List<string>();

            if (severityCounts["Critical"] > 0)
            {
                recommendations.Add("Immediately address all critical vulnerabilities - these pose an immediate security risk");
            }

            if (severityCounts["High"] > 0)
            {
                recommendations.Add("Prioritize high severity vulnerabilities for remediation within 30 days");
            }

            if (vulnerabilities.OfType<CredentialVulnerability>().Any())
            {
                recommendations.Add("Implement strong password policies and multi-factor authentication");
            }

            if (vulnerabilities.OfType<WebVulnerability>().Any())
            {
                recommendations.Add("Conduct comprehensive web application security testing");
            }

            recommendations.Add("Implement regular vulnerability scanning and patch management processes");
            recommendations.Add("Conduct security awareness training for all personnel");
            recommendations.Add("Establish incident response procedures");

            return recommendations;
        }

        private Dictionary<string, int> CalculateComplianceScores(List<object> vulnerabilities)
        {
            var scores = new Dictionary<string, int>();

            // NIST Cybersecurity Framework compliance
            var nistScore = 100;
            nistScore -= vulnerabilities.OfType<CredentialVulnerability>().Count() * 10;
            nistScore -= vulnerabilities.OfType<WebVulnerability>().Count() * 5;
            scores["NIST CSF"] = Math.Max(0, nistScore);

            // OWASP compliance
            var owaspScore = 100;
            owaspScore -= vulnerabilities.OfType<WebVulnerability>().Count() * 15;
            scores["OWASP Top 10"] = Math.Max(0, owaspScore);

            // ISO 27001 compliance
            var isoScore = 100;
            isoScore -= vulnerabilities.Count() * 3;
            scores["ISO 27001"] = Math.Max(0, isoScore);

            return scores;
        }
    }

    #region Report Generators

    /// <summary>
    /// Base interface for report generators
    /// </summary>
    public interface IReportGenerator
    {
        string FileExtension { get; }
        Task<string> GenerateReportAsync(SecurityAssessmentData data);
    }

    /// <summary>
    /// HTML report generator
    /// </summary>
    public class HtmlReportGenerator : IReportGenerator
    {
        public string FileExtension => ".html";

        public async Task<string> GenerateReportAsync(SecurityAssessmentData data)
        {
            var html = new StringBuilder();
            
            html.AppendLine("<!DOCTYPE html>");
            html.AppendLine("<html>");
            html.AppendLine("<head>");
            html.AppendLine("<title>Security Assessment Report</title>");
            html.AppendLine("<style>");
            html.AppendLine(GetCssStyles());
            html.AppendLine("</style>");
            html.AppendLine("</head>");
            html.AppendLine("<body>");
            
            // Header
            html.AppendLine("<div class='header'>");
            html.AppendLine("<h1>🔒 Security Assessment Report</h1>");
            html.AppendLine($"<p>Generated on: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
            html.AppendLine("</div>");

            // Summary section
            html.AppendLine("<div class='section'>");
            html.AppendLine("<h2>📊 Assessment Summary</h2>");
            html.AppendLine($"<p><strong>Scope:</strong> {data.ScanScope}</p>");
            html.AppendLine($"<p><strong>Hosts Scanned:</strong> {data.HostsScanned}</p>");
            html.AppendLine($"<p><strong>Active Hosts:</strong> {data.ActiveHosts}</p>");
            html.AppendLine($"<p><strong>Total Vulnerabilities:</strong> {data.AllVulnerabilities.Count()}</p>");
            html.AppendLine("</div>");

            // Vulnerabilities section
            if (data.AllVulnerabilities.Any())
            {
                html.AppendLine("<div class='section'>");
                html.AppendLine("<h2>🚨 Discovered Vulnerabilities</h2>");
                html.AppendLine("<table>");
                html.AppendLine("<tr><th>Target</th><th>Type</th><th>Severity</th><th>Description</th></tr>");
                
                foreach (var vuln in data.AllVulnerabilities.Take(50)) // Limit for performance
                {
                    var (target, type, severity, description) = ExtractVulnerabilityInfo(vuln);
                    var severityClass = severity.ToLower();
                    html.AppendLine($"<tr><td>{target}</td><td>{type}</td><td class='{severityClass}'>{severity}</td><td>{description}</td></tr>");
                }
                
                html.AppendLine("</table>");
                html.AppendLine("</div>");
            }

            // Recommendations section
            html.AppendLine("<div class='section'>");
            html.AppendLine("<h2>💡 Recommendations</h2>");
            html.AppendLine("<ul>");
            html.AppendLine("<li>Implement regular vulnerability scanning</li>");
            html.AppendLine("<li>Keep all systems updated with latest security patches</li>");
            html.AppendLine("<li>Enforce strong password policies</li>");
            html.AppendLine("<li>Deploy network segmentation</li>");
            html.AppendLine("<li>Conduct regular security training</li>");
            html.AppendLine("</ul>");
            html.AppendLine("</div>");

            html.AppendLine("</body>");
            html.AppendLine("</html>");

            return await Task.FromResult(html.ToString());
        }

        private string GetCssStyles()
        {
            return @"
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
                .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { margin: 0; font-size: 2.5em; }
                h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f2f2f2; font-weight: bold; }
                .critical { background-color: #ffebee; color: #c62828; }
                .high { background-color: #fff3e0; color: #ef6c00; }
                .medium { background-color: #f3e5f5; color: #8e24aa; }
                .low { background-color: #e8f5e8; color: #2e7d32; }
                ul { list-style-type: none; padding: 0; }
                li { background: #f8f9fa; margin: 10px 0; padding: 15px; border-left: 4px solid #667eea; border-radius: 5px; }
            ";
        }

        private (string target, string type, string severity, string description) ExtractVulnerabilityInfo(object vuln)
        {
            return vuln switch
            {
                CredentialVulnerability cv => (cv.Target.ToString(), "Credential", cv.Severity, cv.Description),
                WebVulnerability wv => (wv.Url ?? "Unknown", "Web", wv.Severity, wv.Description ?? "Unknown"),
                _ => ("Unknown", "Unknown", "Info", "Unknown vulnerability type")
            };
        }
    }

    /// <summary>
    /// PDF report generator (simplified - would use a PDF library in production)
    /// </summary>
    public class PdfReportGenerator : IReportGenerator
    {
        public string FileExtension => ".txt"; // Simplified as text for now

        public async Task<string> GenerateReportAsync(SecurityAssessmentData data)
        {
            var content = new StringBuilder();
            
            content.AppendLine("SECURITY ASSESSMENT REPORT");
            content.AppendLine("========================");
            content.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            content.AppendLine();
            
            content.AppendLine("ASSESSMENT SUMMARY");
            content.AppendLine("-----------------");
            content.AppendLine($"Scope: {data.ScanScope}");
            content.AppendLine($"Hosts Scanned: {data.HostsScanned}");
            content.AppendLine($"Active Hosts: {data.ActiveHosts}");
            content.AppendLine($"Vulnerabilities Found: {data.AllVulnerabilities.Count()}");
            content.AppendLine();

            if (data.AllVulnerabilities.Any())
            {
                content.AppendLine("VULNERABILITIES");
                content.AppendLine("--------------");
                
                foreach (var vuln in data.AllVulnerabilities.Take(20))
                {
                    var (target, type, severity, description) = ExtractVulnerabilityInfo(vuln);
                    content.AppendLine($"Target: {target}");
                    content.AppendLine($"Type: {type}");
                    content.AppendLine($"Severity: {severity}");
                    content.AppendLine($"Description: {description}");
                    content.AppendLine();
                }
            }

            content.AppendLine("RECOMMENDATIONS");
            content.AppendLine("--------------");
            content.AppendLine("1. Implement regular vulnerability scanning");
            content.AppendLine("2. Keep systems updated with security patches");
            content.AppendLine("3. Enforce strong password policies");
            content.AppendLine("4. Deploy network segmentation");
            content.AppendLine("5. Conduct security training");

            return await Task.FromResult(content.ToString());
        }

        private (string target, string type, string severity, string description) ExtractVulnerabilityInfo(object vuln)
        {
            return vuln switch
            {
                CredentialVulnerability cv => (cv.Target.ToString(), "Credential", cv.Severity, cv.Description),
                WebVulnerability wv => (wv.Url ?? "Unknown", "Web", wv.Severity, wv.Description ?? "Unknown"),
                _ => ("Unknown", "Unknown", "Info", "Unknown vulnerability")
            };
        }
    }

    /// <summary>
    /// JSON report generator
    /// </summary>
    public class JsonReportGenerator : IReportGenerator
    {
        public string FileExtension => ".json";

        public async Task<string> GenerateReportAsync(SecurityAssessmentData data)
        {
            var reportData = new
            {
                ReportMetadata = new
                {
                    GeneratedAt = DateTime.UtcNow,
                    Version = "1.0",
                    Generator = "On-Prem Network InfraIQ"
                },
                AssessmentSummary = new
                {
                    data.ScanScope,
                    data.HostsScanned,
                    data.ActiveHosts,
                    VulnerabilityCount = data.AllVulnerabilities.Count()
                },
                Vulnerabilities = data.AllVulnerabilities.Select(v => new
                {
                    Type = v.GetType().Name,
                    Data = v
                }).ToArray(),
                ScanResults = data.ScanResults.Take(100).ToArray() // Limit for performance
            };

            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            return await Task.FromResult(JsonSerializer.Serialize(reportData, options));
        }
    }

    /// <summary>
    /// CSV report generator
    /// </summary>
    public class CsvReportGenerator : IReportGenerator
    {
        public string FileExtension => ".csv";

        public async Task<string> GenerateReportAsync(SecurityAssessmentData data)
        {
            var csv = new StringBuilder();
            
            // Vulnerabilities CSV
            csv.AppendLine("Target,Type,Severity,Description,Discovered");
            
            foreach (var vuln in data.AllVulnerabilities)
            {
                var (target, type, severity, description) = ExtractVulnerabilityInfo(vuln);
                csv.AppendLine($"\"{target}\",\"{type}\",\"{severity}\",\"{description}\",\"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\"");
            }

            return await Task.FromResult(csv.ToString());
        }

        private (string target, string type, string severity, string description) ExtractVulnerabilityInfo(object vuln)
        {
            return vuln switch
            {
                CredentialVulnerability cv => (cv.Target.ToString(), "Credential", cv.Severity, cv.Description.Replace("\"", "\"\"")),
                WebVulnerability wv => (wv.Url ?? "Unknown", "Web", wv.Severity, (wv.Description ?? "Unknown").Replace("\"", "\"\"")),
                _ => ("Unknown", "Unknown", "Info", "Unknown vulnerability")
            };
        }
    }

    /// <summary>
    /// Executive report generator
    /// </summary>
    public class ExecutiveReportGenerator : IReportGenerator
    {
        public string FileExtension => ".md";

        public async Task<string> GenerateReportAsync(SecurityAssessmentData data)
        {
            var reporter = new AdvancedReporter();
            return await reporter.GenerateExecutiveSummaryAsync(data);
        }
    }

    #endregion

    #region Data Models

    /// <summary>
    /// Security assessment data container
    /// </summary>
    public class SecurityAssessmentData
    {
        public string ScanScope { get; set; } = string.Empty;
        public int HostsScanned { get; set; }
        public int ActiveHosts { get; set; }
        public IEnumerable<ScanResult> ScanResults { get; set; } = Enumerable.Empty<ScanResult>();
        public IEnumerable<object> AllVulnerabilities { get; set; } = Enumerable.Empty<object>();
        public DateTime AssessmentDate { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Risk assessment results
    /// </summary>
    public class RiskAssessment
    {
        public Dictionary<string, int> SeverityDistribution { get; set; } = new();
        public int OverallRiskScore { get; set; }
        public string RiskLevel { get; set; } = string.Empty;
        public List<string> Recommendations { get; set; } = new();
        public Dictionary<string, int> ComplianceScores { get; set; } = new();
    }

    /// <summary>
    /// Report types
    /// </summary>
    public enum ReportType
    {
        Html,
        Pdf,
        Json,
        Csv,
        Executive
    }

    #endregion
}