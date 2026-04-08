using Discovery.Core.Data;
using Discovery.Core.Models;
using Discovery.Core.Repositories;
using Discovery.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Discovery.Services.Data;

/// <summary>
/// Main database service that provides access to all database operations.
/// </summary>
public class DatabaseService
{
    private readonly NetworkDiscoveryDbContext _context;
    private readonly IScanSessionRepository _sessionRepository;
    private readonly IScanResultRepository _resultRepository;
    private readonly IVulnerabilityRepository _vulnerabilityRepository;
    private readonly IAnomalyDetectionRepository _anomalyRepository;
    private readonly ICloudResourceRepository _cloudResourceRepository;

    /// <summary>
    /// Initializes a new instance of the <see cref="DatabaseService"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public DatabaseService(NetworkDiscoveryDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        
        // Initialize repositories
        _sessionRepository = new ScanSessionRepository(_context);
        _resultRepository = new ScanResultRepository(_context);
        _vulnerabilityRepository = new VulnerabilityRepository(_context);
        _anomalyRepository = new AnomalyDetectionRepository(_context);
        _cloudResourceRepository = new CloudResourceRepository(_context);
    }

    /// <summary>
    /// Gets the scan session repository.
    /// </summary>
    public IScanSessionRepository Sessions => _sessionRepository;

    /// <summary>
    /// Gets the scan result repository.
    /// </summary>
    public IScanResultRepository Results => _resultRepository;

    /// <summary>
    /// Gets the vulnerability repository.
    /// </summary>
    public IVulnerabilityRepository Vulnerabilities => _vulnerabilityRepository;

    /// <summary>
    /// Gets the anomaly detection repository.
    /// </summary>
    public IAnomalyDetectionRepository Anomalies => _anomalyRepository;

    /// <summary>
    /// Gets the cloud resource repository.
    /// </summary>
    public ICloudResourceRepository CloudResources => _cloudResourceRepository;

    /// <summary>
    /// Initializes the database, creating it if it doesn't exist.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if the database was created or already exists.</returns>
    public async Task<bool> InitializeDatabaseAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await _context.Database.EnsureCreatedAsync(cancellationToken);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to initialize database: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Applies any pending database migrations.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if migrations were applied successfully.</returns>
    public async Task<bool> MigrateDatabaseAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await _context.Database.MigrateAsync(cancellationToken);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to migrate database: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Creates a complete scan session with results, vulnerabilities, and anomalies.
    /// </summary>
    /// <param name="sessionName">The name of the scan session.</param>
    /// <param name="scanType">The type of scan performed.</param>
    /// <param name="target">The target that was scanned.</param>
    /// <param name="results">The scan results.</param>
    /// <param name="vulnerabilities">The vulnerabilities found.</param>
    /// <param name="anomalies">The anomalies detected.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created scan session.</returns>
    public async Task<ScanSession> CreateCompleteScanSessionAsync(
        string sessionName,
        string scanType,
        string target,
        IEnumerable<ScanResult> results,
        IEnumerable<VulnerabilityResultEntity>? vulnerabilities = null,
        IEnumerable<AnomalyDetectionResult>? anomalies = null,
        CancellationToken cancellationToken = default)
    {
        using var transaction = await _context.Database.BeginTransactionAsync(cancellationToken);
        
        try
        {
            // Create scan session
            var session = new ScanSession
            {
                Name = sessionName,
                ScanType = scanType,
                Target = target,
                StartedAt = DateTime.UtcNow,
                CompletedAt = DateTime.UtcNow
            };

            session = await _sessionRepository.CreateSessionAsync(session, cancellationToken);

            // Add scan results
            if (results.Any())
            {
                await _resultRepository.AddResultsAsync(session.Id, results, cancellationToken);
            }

            // Add vulnerabilities
            if (vulnerabilities?.Any() == true)
            {
                await _vulnerabilityRepository.AddVulnerabilitiesAsync(session.Id, vulnerabilities, cancellationToken);
            }

            // Add anomalies
            if (anomalies?.Any() == true)
            {
                await _anomalyRepository.AddAnomaliesAsync(session.Id, anomalies, cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
            return session;
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    /// <summary>
    /// Gets comprehensive scan statistics.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Database statistics.</returns>
    public async Task<DatabaseStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default)
    {
        var totalSessions = await _context.ScanSessions.CountAsync(cancellationToken);
        var totalResults = await _context.ScanResults.CountAsync(cancellationToken);
        var totalVulnerabilities = await _context.VulnerabilityResults.CountAsync(cancellationToken);
        var totalAnomalies = await _context.AnomalyDetectionResults.CountAsync(cancellationToken);
        var totalCloudResources = await _context.CloudResources.CountAsync(cancellationToken);

        var recentSession = await _context.ScanSessions
            .OrderByDescending(s => s.StartedAt)
            .FirstOrDefaultAsync(cancellationToken);

        var topVulnerablePorts = await _context.ScanResults
            .Where(r => r.IsVulnerable)
            .GroupBy(r => r.Port)
            .Select(g => new { Port = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .Take(10)
            .ToListAsync(cancellationToken);

        return new DatabaseStatistics
        {
            TotalScanSessions = totalSessions,
            TotalScanResults = totalResults,
            TotalVulnerabilities = totalVulnerabilities,
            TotalAnomalies = totalAnomalies,
            TotalCloudResources = totalCloudResources,
            LastScanDate = recentSession?.StartedAt,
            TopVulnerablePorts = topVulnerablePorts.ToDictionary(x => x.Port, x => x.Count)
        };
    }

    /// <summary>
    /// Cleans up old scan data based on retention policy.
    /// </summary>
    /// <param name="retentionDays">Number of days to retain data.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Number of sessions deleted.</returns>
    public async Task<int> CleanupOldDataAsync(int retentionDays = 90, CancellationToken cancellationToken = default)
    {
        var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);
        
        var oldSessions = await _context.ScanSessions
            .Where(s => s.StartedAt < cutoffDate)
            .ToListAsync(cancellationToken);

        if (oldSessions.Any())
        {
            _context.ScanSessions.RemoveRange(oldSessions);
            await _context.SaveChangesAsync(cancellationToken);
        }

        return oldSessions.Count;
    }

    /// <summary>
    /// Exports scan data to JSON format.
    /// </summary>
    /// <param name="sessionId">The session ID to export.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>JSON export of the scan session.</returns>
    public async Task<string> ExportSessionToJsonAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        var session = await _context.ScanSessions
            .Include(s => s.ScanResults)
            .Include(s => s.VulnerabilityResults)
            .FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);

        if (session == null)
        {
            throw new ArgumentException("Session not found", nameof(sessionId));
        }

        var exportData = new
        {
            Session = new
            {
                session.Id,
                session.Name,
                session.ScanType,
                session.Target,
                session.StartedAt,
                session.CompletedAt,
                session.ResultCount
            },
            Results = session.ScanResults.Select(r => new
            {
                r.IpAddress,
                r.Port,
                r.IsOpen,
                r.Service,
                r.ServiceName,
                r.OperatingSystem,
                r.Country,
                r.Hostname,
                r.IsVulnerable,
                r.VulnerabilityInfo,
                r.DiscoveredAt
            }),
            Vulnerabilities = session.VulnerabilityResults.Select(v => new
            {
                v.IpAddress,
                v.Port,
                v.Title,
                v.Description,
                v.Severity,
                v.RecommendedFix,
                v.CveId,
                v.DiscoveredAt
            })
        };

        return System.Text.Json.JsonSerializer.Serialize(exportData, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true
        });
    }
}

/// <summary>
/// Database statistics information.
/// </summary>
public class DatabaseStatistics
{
    /// <summary>
    /// Gets or sets the total number of scan sessions.
    /// </summary>
    public int TotalScanSessions { get; set; }

    /// <summary>
    /// Gets or sets the total number of scan results.
    /// </summary>
    public int TotalScanResults { get; set; }

    /// <summary>
    /// Gets or sets the total number of vulnerabilities.
    /// </summary>
    public int TotalVulnerabilities { get; set; }

    /// <summary>
    /// Gets or sets the total number of anomalies.
    /// </summary>
    public int TotalAnomalies { get; set; }

    /// <summary>
    /// Gets or sets the total number of cloud resources.
    /// </summary>
    public int TotalCloudResources { get; set; }

    /// <summary>
    /// Gets or sets the date of the last scan.
    /// </summary>
    public DateTime? LastScanDate { get; set; }

    /// <summary>
    /// Gets or sets the top vulnerable ports.
    /// </summary>
    public Dictionary<int, int> TopVulnerablePorts { get; set; } = new();
}