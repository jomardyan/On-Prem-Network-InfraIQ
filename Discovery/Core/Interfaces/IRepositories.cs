using Discovery.Core.Models;

namespace Discovery.Core.Interfaces;

/// <summary>
/// Interface for accessing scan session data.
/// </summary>
public interface IScanSessionRepository
{
    /// <summary>
    /// Creates a new scan session.
    /// </summary>
    /// <param name="session">The scan session to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created scan session.</returns>
    Task<ScanSession> CreateSessionAsync(ScanSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a scan session by ID.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The scan session if found.</returns>
    Task<ScanSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all scan sessions.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan sessions.</returns>
    Task<IEnumerable<ScanSession>> GetSessionsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a scan session.
    /// </summary>
    /// <param name="session">The scan session to update.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The updated scan session.</returns>
    Task<ScanSession> UpdateSessionAsync(ScanSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a scan session and all associated data.
    /// </summary>
    /// <param name="sessionId">The session ID to delete.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if the session was deleted.</returns>
    Task<bool> DeleteSessionAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets scan sessions by type.
    /// </summary>
    /// <param name="scanType">The scan type to filter by.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan sessions.</returns>
    Task<IEnumerable<ScanSession>> GetSessionsByScanTypeAsync(string scanType, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets recent scan sessions.
    /// </summary>
    /// <param name="count">The number of sessions to retrieve.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of recent scan sessions.</returns>
    Task<IEnumerable<ScanSession>> GetRecentSessionsAsync(int count = 10, CancellationToken cancellationToken = default);
}

/// <summary>
/// Interface for accessing scan result data.
/// </summary>
public interface IScanResultRepository
{
    /// <summary>
    /// Adds scan results to a session.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="results">The scan results to add.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The number of results added.</returns>
    Task<int> AddResultsAsync(Guid sessionId, IEnumerable<ScanResult> results, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets scan results for a session.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan results.</returns>
    Task<IEnumerable<ScanResult>> GetResultsAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets scan results by IP address.
    /// </summary>
    /// <param name="ipAddress">The IP address to filter by.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan results.</returns>
    Task<IEnumerable<ScanResult>> GetResultsByIpAsync(string ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets scan results with open ports.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan results with open ports.</returns>
    Task<IEnumerable<ScanResult>> GetOpenPortsAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets scan results with vulnerabilities.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan results with vulnerabilities.</returns>
    Task<IEnumerable<ScanResult>> GetVulnerableResultsAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets scan results by IPv6.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of IPv6 scan results.</returns>
    Task<IEnumerable<ScanResult>> GetIPv6ResultsAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Searches scan results by various criteria.
    /// </summary>
    /// <param name="searchCriteria">The search criteria.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of matching scan results.</returns>
    Task<IEnumerable<ScanResult>> SearchResultsAsync(ScanResultSearchCriteria searchCriteria, CancellationToken cancellationToken = default);
}

/// <summary>
/// Interface for accessing vulnerability data.
/// </summary>
public interface IVulnerabilityRepository
{
    /// <summary>
    /// Adds vulnerability results to a session.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="vulnerabilities">The vulnerability results to add.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The number of vulnerabilities added.</returns>
    Task<int> AddVulnerabilitiesAsync(Guid sessionId, IEnumerable<VulnerabilityResultEntity> vulnerabilities, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets vulnerability results for a session.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of vulnerability results.</returns>
    Task<IEnumerable<VulnerabilityResultEntity>> GetVulnerabilitiesAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets vulnerabilities by severity.
    /// </summary>
    /// <param name="severity">The vulnerability severity.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of vulnerability results.</returns>
    Task<IEnumerable<VulnerabilityResultEntity>> GetVulnerabilitiesBySeverityAsync(VulnerabilitySeverity severity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets vulnerabilities by IP address.
    /// </summary>
    /// <param name="ipAddress">The IP address.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of vulnerability results.</returns>
    Task<IEnumerable<VulnerabilityResultEntity>> GetVulnerabilitiesByIpAsync(string ipAddress, CancellationToken cancellationToken = default);
}

/// <summary>
/// Interface for accessing anomaly detection data.
/// </summary>
public interface IAnomalyDetectionRepository
{
    /// <summary>
    /// Adds anomaly detection results to a session.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="anomalies">The anomaly results to add.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The number of anomalies added.</returns>
    Task<int> AddAnomaliesAsync(Guid sessionId, IEnumerable<AnomalyDetectionResult> anomalies, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets anomaly detection results for a session.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of anomaly detection results.</returns>
    Task<IEnumerable<AnomalyDetectionResult>> GetAnomaliesAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets anomalies by score threshold.
    /// </summary>
    /// <param name="minScore">The minimum anomaly score.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of anomaly detection results.</returns>
    Task<IEnumerable<AnomalyDetectionResult>> GetAnomaliesByScoreAsync(double minScore, CancellationToken cancellationToken = default);
}

/// <summary>
/// Interface for accessing cloud resource data.
/// </summary>
public interface ICloudResourceRepository
{
    /// <summary>
    /// Adds cloud resources.
    /// </summary>
    /// <param name="resources">The cloud resources to add.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The number of resources added.</returns>
    Task<int> AddResourcesAsync(IEnumerable<CloudResourceEntity> resources, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all cloud resources.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of cloud resources.</returns>
    Task<IEnumerable<CloudResourceEntity>> GetResourcesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets cloud resources by provider.
    /// </summary>
    /// <param name="cloudProvider">The cloud provider.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of cloud resources.</returns>
    Task<IEnumerable<CloudResourceEntity>> GetResourcesByProviderAsync(string cloudProvider, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets cloud resources by region.
    /// </summary>
    /// <param name="cloudProvider">The cloud provider.</param>
    /// <param name="region">The region.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of cloud resources.</returns>
    Task<IEnumerable<CloudResourceEntity>> GetResourcesByRegionAsync(string cloudProvider, string region, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a cloud resource.
    /// </summary>
    /// <param name="resource">The cloud resource to update.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The updated cloud resource.</returns>
    Task<CloudResourceEntity> UpdateResourceAsync(CloudResourceEntity resource, CancellationToken cancellationToken = default);
}

/// <summary>
/// Search criteria for scan results.
/// </summary>
public class ScanResultSearchCriteria
{
    /// <summary>
    /// Gets or sets the session ID to filter by.
    /// </summary>
    public Guid? SessionId { get; set; }

    /// <summary>
    /// Gets or sets the IP address to filter by.
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// Gets or sets the port range to filter by.
    /// </summary>
    public (int Min, int Max)? PortRange { get; set; }

    /// <summary>
    /// Gets or sets whether to filter by open ports only.
    /// </summary>
    public bool? OpenPortsOnly { get; set; }

    /// <summary>
    /// Gets or sets whether to filter by vulnerable results only.
    /// </summary>
    public bool? VulnerableOnly { get; set; }

    /// <summary>
    /// Gets or sets the service name to filter by.
    /// </summary>
    public string? ServiceName { get; set; }

    /// <summary>
    /// Gets or sets the IP version to filter by (4 or 6).
    /// </summary>
    public int? IpVersion { get; set; }

    /// <summary>
    /// Gets or sets the date range to filter by.
    /// </summary>
    public (DateTime From, DateTime To)? DateRange { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of results to return.
    /// </summary>
    public int? MaxResults { get; set; }
}