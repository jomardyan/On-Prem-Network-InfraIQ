using Discovery.Core.Data;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Discovery.Core.Repositories;

/// <summary>
/// Repository implementation for scan session data access.
/// </summary>
public class ScanSessionRepository : IScanSessionRepository
{
    private readonly NetworkDiscoveryDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="ScanSessionRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public ScanSessionRepository(NetworkDiscoveryDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<ScanSession> CreateSessionAsync(ScanSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        _context.ScanSessions.Add(session);
        await _context.SaveChangesAsync(cancellationToken);
        return session;
    }

    /// <inheritdoc />
    public async Task<ScanSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        return await _context.ScanSessions
            .Include(s => s.ScanResults)
            .Include(s => s.VulnerabilityResults)
            .FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanSession>> GetSessionsAsync(CancellationToken cancellationToken = default)
    {
        return await _context.ScanSessions
            .OrderByDescending(s => s.StartedAt)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<ScanSession> UpdateSessionAsync(ScanSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        _context.ScanSessions.Update(session);
        await _context.SaveChangesAsync(cancellationToken);
        return session;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        var session = await _context.ScanSessions.FindAsync(new object[] { sessionId }, cancellationToken);
        if (session == null)
        {
            return false;
        }

        _context.ScanSessions.Remove(session);
        await _context.SaveChangesAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanSession>> GetSessionsByScanTypeAsync(string scanType, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scanType);

        return await _context.ScanSessions
            .Where(s => s.ScanType == scanType)
            .OrderByDescending(s => s.StartedAt)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanSession>> GetRecentSessionsAsync(int count = 10, CancellationToken cancellationToken = default)
    {
        return await _context.ScanSessions
            .OrderByDescending(s => s.StartedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }
}

/// <summary>
/// Repository implementation for scan result data access.
/// </summary>
public class ScanResultRepository : IScanResultRepository
{
    private readonly NetworkDiscoveryDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="ScanResultRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public ScanResultRepository(NetworkDiscoveryDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<int> AddResultsAsync(Guid sessionId, IEnumerable<ScanResult> results, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(results);

        var entities = results.Select(r => ScanResultEntity.FromScanResult(r, sessionId));
        _context.ScanResults.AddRange(entities);
        
        var count = await _context.SaveChangesAsync(cancellationToken);
        
        // Update the session result count
        var session = await _context.ScanSessions.FindAsync(new object[] { sessionId }, cancellationToken);
        if (session != null)
        {
            session.ResultCount = await _context.ScanResults.CountAsync(r => r.ScanSessionId == sessionId, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        return count;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanResult>> GetResultsAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        var entities = await _context.ScanResults
            .Where(r => r.ScanSessionId == sessionId)
            .OrderBy(r => r.IpAddress)
            .ThenBy(r => r.Port)
            .ToListAsync(cancellationToken);

        return entities.Select(e => e.ToScanResult());
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanResult>> GetResultsByIpAsync(string ipAddress, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipAddress);

        var entities = await _context.ScanResults
            .Where(r => r.IpAddress == ipAddress)
            .OrderByDescending(r => r.DiscoveredAt)
            .ToListAsync(cancellationToken);

        return entities.Select(e => e.ToScanResult());
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanResult>> GetOpenPortsAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        var entities = await _context.ScanResults
            .Where(r => r.ScanSessionId == sessionId && r.IsOpen)
            .OrderBy(r => r.IpAddress)
            .ThenBy(r => r.Port)
            .ToListAsync(cancellationToken);

        return entities.Select(e => e.ToScanResult());
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanResult>> GetVulnerableResultsAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        var entities = await _context.ScanResults
            .Where(r => r.ScanSessionId == sessionId && r.IsVulnerable)
            .OrderBy(r => r.IpAddress)
            .ThenBy(r => r.Port)
            .ToListAsync(cancellationToken);

        return entities.Select(e => e.ToScanResult());
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanResult>> GetIPv6ResultsAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        var entities = await _context.ScanResults
            .Where(r => r.ScanSessionId == sessionId && r.IpVersion == 6)
            .OrderBy(r => r.IpAddress)
            .ThenBy(r => r.Port)
            .ToListAsync(cancellationToken);

        return entities.Select(e => e.ToScanResult());
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ScanResult>> SearchResultsAsync(ScanResultSearchCriteria searchCriteria, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(searchCriteria);

        var query = _context.ScanResults.AsQueryable();

        if (searchCriteria.SessionId.HasValue)
        {
            query = query.Where(r => r.ScanSessionId == searchCriteria.SessionId.Value);
        }

        if (!string.IsNullOrWhiteSpace(searchCriteria.IpAddress))
        {
            query = query.Where(r => r.IpAddress.Contains(searchCriteria.IpAddress));
        }

        if (searchCriteria.PortRange.HasValue)
        {
            var (min, max) = searchCriteria.PortRange.Value;
            query = query.Where(r => r.Port >= min && r.Port <= max);
        }

        if (searchCriteria.OpenPortsOnly.HasValue)
        {
            query = query.Where(r => r.IsOpen == searchCriteria.OpenPortsOnly.Value);
        }

        if (searchCriteria.VulnerableOnly.HasValue)
        {
            query = query.Where(r => r.IsVulnerable == searchCriteria.VulnerableOnly.Value);
        }

        if (!string.IsNullOrWhiteSpace(searchCriteria.ServiceName))
        {
            query = query.Where(r => r.ServiceName.Contains(searchCriteria.ServiceName));
        }

        if (searchCriteria.IpVersion.HasValue)
        {
            query = query.Where(r => r.IpVersion == searchCriteria.IpVersion.Value);
        }

        if (searchCriteria.DateRange.HasValue)
        {
            var (from, to) = searchCriteria.DateRange.Value;
            query = query.Where(r => r.DiscoveredAt >= from && r.DiscoveredAt <= to);
        }

        query = query.OrderBy(r => r.IpAddress).ThenBy(r => r.Port);

        if (searchCriteria.MaxResults.HasValue)
        {
            query = query.Take(searchCriteria.MaxResults.Value);
        }

        var entities = await query.ToListAsync(cancellationToken);
        return entities.Select(e => e.ToScanResult());
    }
}