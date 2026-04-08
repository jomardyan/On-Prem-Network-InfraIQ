using Discovery.Core.Data;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Discovery.Services.Data;
using Microsoft.EntityFrameworkCore;

namespace Discovery.Services.Integration;

/// <summary>
/// Service for integrating scan results with database storage.
/// Provides seamless integration between scanners and the database layer.
/// </summary>
public class ScanResultIntegrationService : IDisposable
{
    private readonly DatabaseService _databaseService;
    private readonly NetworkDiscoveryDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="ScanResultIntegrationService"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    public ScanResultIntegrationService(NetworkDiscoveryDbContext? context = null)
    {
        _context = context ?? CreateDefaultContext();
        _databaseService = new DatabaseService(_context);
    }

    /// <summary>
    /// Initializes the database and ensures it's ready for use.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if initialization was successful.</returns>
    public async Task<bool> InitializeAsync(CancellationToken cancellationToken = default)
    {
        return await _databaseService.InitializeDatabaseAsync(cancellationToken);
    }

    /// <summary>
    /// Saves scan results to the database and returns the session ID.
    /// </summary>
    /// <param name="scanResults">The scan results to save.</param>
    /// <param name="scanType">The type of scan performed.</param>
    /// <param name="target">The target that was scanned.</param>
    /// <param name="sessionName">Optional custom session name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created scan session.</returns>
    public async Task<ScanSession> SaveScanResultsAsync(
        IEnumerable<ScanResult> scanResults,
        string scanType,
        string target,
        string? sessionName = null,
        CancellationToken cancellationToken = default)
    {
        sessionName ??= $"{scanType} - {target} - {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}";

        try
        {
            var session = await _databaseService.CreateCompleteScanSessionAsync(
                sessionName,
                scanType,
                target,
                scanResults,
                cancellationToken: cancellationToken
            );

            Console.WriteLine($"💾 Saved {scanResults.Count()} scan results to database (Session: {session.Id})");
            return session;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to save scan results to database: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Retrieves recent scan sessions.
    /// </summary>
    /// <param name="count">Number of sessions to retrieve.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of recent scan sessions.</returns>
    public async Task<IEnumerable<ScanSession>> GetRecentScansAsync(int count = 10, CancellationToken cancellationToken = default)
    {
        return await _databaseService.Sessions.GetRecentSessionsAsync(count, cancellationToken);
    }

    /// <summary>
    /// Retrieves scan results for a specific session.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan results.</returns>
    public async Task<IEnumerable<ScanResult>> GetScanResultsAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        return await _databaseService.Results.GetResultsAsync(sessionId, cancellationToken);
    }

    /// <summary>
    /// Searches scan results based on criteria.
    /// </summary>
    /// <param name="searchCriteria">The search criteria.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of matching scan results.</returns>
    public async Task<IEnumerable<ScanResult>> SearchScanResultsAsync(
        ScanResultSearchCriteria searchCriteria,
        CancellationToken cancellationToken = default)
    {
        return await _databaseService.Results.SearchResultsAsync(searchCriteria, cancellationToken);
    }

    /// <summary>
    /// Gets database statistics.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Database statistics.</returns>
    public async Task<DatabaseStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default)
    {
        return await _databaseService.GetStatisticsAsync(cancellationToken);
    }

    /// <summary>
    /// Exports a scan session to JSON.
    /// </summary>
    /// <param name="sessionId">The session ID to export.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>JSON export of the scan session.</returns>
    public async Task<string> ExportSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        return await _databaseService.ExportSessionToJsonAsync(sessionId, cancellationToken);
    }

    /// <summary>
    /// Cleans up old scan data.
    /// </summary>
    /// <param name="retentionDays">Number of days to retain data.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Number of sessions deleted.</returns>
    public async Task<int> CleanupOldDataAsync(int retentionDays = 90, CancellationToken cancellationToken = default)
    {
        return await _databaseService.CleanupOldDataAsync(retentionDays, cancellationToken);
    }

    /// <summary>
    /// Creates a default database context.
    /// </summary>
    /// <returns>A configured database context.</returns>
    private static NetworkDiscoveryDbContext CreateDefaultContext()
    {
        var options = new DbContextOptionsBuilder<NetworkDiscoveryDbContext>()
            .UseSqlite(GetDefaultConnectionString())
            .Options;

        return new NetworkDiscoveryDbContext(options);
    }

    /// <summary>
    /// Gets the default SQLite connection string.
    /// </summary>
    /// <returns>The connection string.</returns>
    private static string GetDefaultConnectionString()
    {
        var databasePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AdvancedNetworkDiscovery",
            "NetworkDiscovery.db"
        );

        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
        return $"Data Source={databasePath}";
    }

    /// <summary>
    /// Disposes the service and releases resources.
    /// </summary>
    public void Dispose()
    {
        _context?.Dispose();
    }
}

/// <summary>
/// Extension methods for integrating database storage with existing scanners.
/// </summary>
public static class ScannerDatabaseExtensions
{
    /// <summary>
    /// Saves scan results to the database automatically.
    /// </summary>
    /// <param name="scanResults">The scan results.</param>
    /// <param name="scanType">The type of scan.</param>
    /// <param name="target">The scan target.</param>
    /// <param name="sessionName">Optional session name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The scan session.</returns>
    public static async Task<ScanSession> SaveToDatabaseAsync(
        this IEnumerable<ScanResult> scanResults,
        string scanType,
        string target,
        string? sessionName = null,
        CancellationToken cancellationToken = default)
    {
        using var integrationService = new ScanResultIntegrationService();
        await integrationService.InitializeAsync(cancellationToken);
        return await integrationService.SaveScanResultsAsync(scanResults, scanType, target, sessionName, cancellationToken);
    }

    /// <summary>
    /// Prints database statistics to the console.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    public static async Task PrintDatabaseStatisticsAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var integrationService = new ScanResultIntegrationService();
            await integrationService.InitializeAsync(cancellationToken);
            
            var stats = await integrationService.GetStatisticsAsync(cancellationToken);
            
            Console.WriteLine();
            Console.WriteLine("📊 Database Statistics:");
            Console.WriteLine($"   Total Scan Sessions: {stats.TotalScanSessions:N0}");
            Console.WriteLine($"   Total Scan Results: {stats.TotalScanResults:N0}");
            Console.WriteLine($"   Total Vulnerabilities: {stats.TotalVulnerabilities:N0}");
            Console.WriteLine($"   Total Cloud Resources: {stats.TotalCloudResources:N0}");
            Console.WriteLine($"   Last Scan: {stats.LastScanDate?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");

            if (stats.TopVulnerablePorts.Any())
            {
                Console.WriteLine("   Top Vulnerable Ports:");
                foreach (var port in stats.TopVulnerablePorts.Take(5))
                {
                    Console.WriteLine($"     Port {port.Key}: {port.Value} vulnerabilities");
                }
            }
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to retrieve database statistics: {ex.Message}");
        }
    }
}