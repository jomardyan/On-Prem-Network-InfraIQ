using Discovery.Core.Data;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Discovery.Core.Repositories;

/// <summary>
/// Repository implementation for vulnerability data access.
/// </summary>
public class VulnerabilityRepository : IVulnerabilityRepository
{
    private readonly NetworkDiscoveryDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="VulnerabilityRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public VulnerabilityRepository(NetworkDiscoveryDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<int> AddVulnerabilitiesAsync(Guid sessionId, IEnumerable<VulnerabilityResultEntity> vulnerabilities, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(vulnerabilities);

        foreach (var vulnerability in vulnerabilities)
        {
            vulnerability.ScanSessionId = sessionId;
        }

        _context.VulnerabilityResults.AddRange(vulnerabilities);
        return await _context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<VulnerabilityResultEntity>> GetVulnerabilitiesAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        return await _context.VulnerabilityResults
            .Where(v => v.ScanSessionId == sessionId)
            .OrderByDescending(v => v.Severity)
            .ThenBy(v => v.IpAddress)
            .ThenBy(v => v.Port)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<VulnerabilityResultEntity>> GetVulnerabilitiesBySeverityAsync(VulnerabilitySeverity severity, CancellationToken cancellationToken = default)
    {
        return await _context.VulnerabilityResults
            .Where(v => v.Severity == severity)
            .OrderByDescending(v => v.DiscoveredAt)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<VulnerabilityResultEntity>> GetVulnerabilitiesByIpAsync(string ipAddress, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipAddress);

        return await _context.VulnerabilityResults
            .Where(v => v.IpAddress == ipAddress)
            .OrderByDescending(v => v.Severity)
            .ThenByDescending(v => v.DiscoveredAt)
            .ToListAsync(cancellationToken);
    }
}

/// <summary>
/// Repository implementation for anomaly detection data access.
/// </summary>
public class AnomalyDetectionRepository : IAnomalyDetectionRepository
{
    private readonly NetworkDiscoveryDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="AnomalyDetectionRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public AnomalyDetectionRepository(NetworkDiscoveryDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<int> AddAnomaliesAsync(Guid sessionId, IEnumerable<AnomalyDetectionResult> anomalies, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(anomalies);

        foreach (var anomaly in anomalies)
        {
            anomaly.ScanSessionId = sessionId;
        }

        _context.AnomalyDetectionResults.AddRange(anomalies);
        return await _context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<AnomalyDetectionResult>> GetAnomaliesAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        return await _context.AnomalyDetectionResults
            .Where(a => a.ScanSessionId == sessionId)
            .OrderByDescending(a => a.AnomalyScore)
            .ThenByDescending(a => a.DetectedAt)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<AnomalyDetectionResult>> GetAnomaliesByScoreAsync(double minScore, CancellationToken cancellationToken = default)
    {
        return await _context.AnomalyDetectionResults
            .Where(a => a.AnomalyScore >= minScore)
            .OrderByDescending(a => a.AnomalyScore)
            .ThenByDescending(a => a.DetectedAt)
            .ToListAsync(cancellationToken);
    }
}

/// <summary>
/// Repository implementation for cloud resource data access.
/// </summary>
public class CloudResourceRepository : ICloudResourceRepository
{
    private readonly NetworkDiscoveryDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="CloudResourceRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public CloudResourceRepository(NetworkDiscoveryDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<int> AddResourcesAsync(IEnumerable<CloudResourceEntity> resources, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resources);

        // Check for existing resources to avoid duplicates
        var resourceIds = resources.Select(r => r.ResourceId).ToList();
        var existingResources = await _context.CloudResources
            .Where(r => resourceIds.Contains(r.ResourceId))
            .Select(r => r.ResourceId)
            .ToListAsync(cancellationToken);

        var newResources = resources.Where(r => !existingResources.Contains(r.ResourceId));
        
        _context.CloudResources.AddRange(newResources);
        return await _context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<CloudResourceEntity>> GetResourcesAsync(CancellationToken cancellationToken = default)
    {
        return await _context.CloudResources
            .OrderBy(r => r.CloudProvider)
            .ThenBy(r => r.Region)
            .ThenBy(r => r.ResourceName)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<CloudResourceEntity>> GetResourcesByProviderAsync(string cloudProvider, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cloudProvider);

        return await _context.CloudResources
            .Where(r => r.CloudProvider == cloudProvider)
            .OrderBy(r => r.Region)
            .ThenBy(r => r.ResourceName)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<CloudResourceEntity>> GetResourcesByRegionAsync(string cloudProvider, string region, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cloudProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(region);

        return await _context.CloudResources
            .Where(r => r.CloudProvider == cloudProvider && r.Region == region)
            .OrderBy(r => r.ResourceName)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<CloudResourceEntity> UpdateResourceAsync(CloudResourceEntity resource, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        _context.CloudResources.Update(resource);
        await _context.SaveChangesAsync(cancellationToken);
        return resource;
    }
}