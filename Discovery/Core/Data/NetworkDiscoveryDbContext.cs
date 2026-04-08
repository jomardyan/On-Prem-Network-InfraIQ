using Discovery.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Discovery.Core.Data;

/// <summary>
/// Entity Framework DbContext for the On-Prem Network InfraIQ database.
/// </summary>
public class NetworkDiscoveryDbContext : DbContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NetworkDiscoveryDbContext"/> class.
    /// </summary>
    /// <param name="options">The database context options.</param>
    public NetworkDiscoveryDbContext(DbContextOptions<NetworkDiscoveryDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// Gets or sets the scan sessions.
    /// </summary>
    public DbSet<ScanSession> ScanSessions { get; set; } = null!;

    /// <summary>
    /// Gets or sets the scan results.
    /// </summary>
    public DbSet<ScanResultEntity> ScanResults { get; set; } = null!;

    /// <summary>
    /// Gets or sets the vulnerability results.
    /// </summary>
    public DbSet<VulnerabilityResultEntity> VulnerabilityResults { get; set; } = null!;

    /// <summary>
    /// Gets or sets the anomaly detection results.
    /// </summary>
    public DbSet<AnomalyDetectionResult> AnomalyDetectionResults { get; set; } = null!;

    /// <summary>
    /// Gets or sets the cloud resources.
    /// </summary>
    public DbSet<CloudResourceEntity> CloudResources { get; set; } = null!;

    /// <summary>
    /// Configures the database models and relationships.
    /// </summary>
    /// <param name="modelBuilder">The model builder.</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure ScanSession
        modelBuilder.Entity<ScanSession>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(255);
            entity.Property(e => e.ScanType).HasMaxLength(100);
            entity.Property(e => e.Target).HasMaxLength(255);
            entity.HasIndex(e => e.StartedAt);
            entity.HasIndex(e => e.ScanType);
            entity.HasIndex(e => e.Target);
        });

        // Configure ScanResultEntity
        modelBuilder.Entity<ScanResultEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.IpAddress).HasMaxLength(45);
            entity.Property(e => e.Service).HasMaxLength(255);
            entity.Property(e => e.OperatingSystem).HasMaxLength(255);
            entity.Property(e => e.Country).HasMaxLength(100);
            entity.Property(e => e.Hostname).HasMaxLength(255);
            entity.Property(e => e.ServiceName).HasMaxLength(255);
            
            // Relationships
            entity.HasOne(e => e.ScanSession)
                  .WithMany(s => s.ScanResults)
                  .HasForeignKey(e => e.ScanSessionId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Indexes for common queries
            entity.HasIndex(e => e.IpAddress);
            entity.HasIndex(e => e.Port);
            entity.HasIndex(e => e.IsOpen);
            entity.HasIndex(e => e.DiscoveredAt);
            entity.HasIndex(e => e.IsVulnerable);
            entity.HasIndex(e => e.IpVersion);
            entity.HasIndex(e => new { e.IpAddress, e.Port });
        });

        // Configure VulnerabilityResultEntity
        modelBuilder.Entity<VulnerabilityResultEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.IpAddress).HasMaxLength(45);
            entity.Property(e => e.Title).HasMaxLength(255);
            entity.Property(e => e.CveId).HasMaxLength(50);
            
            // Relationships
            entity.HasOne(e => e.ScanSession)
                  .WithMany(s => s.VulnerabilityResults)
                  .HasForeignKey(e => e.ScanSessionId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Indexes
            entity.HasIndex(e => e.IpAddress);
            entity.HasIndex(e => e.Severity);
            entity.HasIndex(e => e.DiscoveredAt);
            entity.HasIndex(e => e.CveId);
        });

        // Configure AnomalyDetectionResult
        modelBuilder.Entity<AnomalyDetectionResult>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.IpAddress).HasMaxLength(45);
            entity.Property(e => e.AnomalyType).HasMaxLength(100);
            
            // Relationships
            entity.HasOne(e => e.ScanSession)
                  .WithMany()
                  .HasForeignKey(e => e.ScanSessionId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Indexes
            entity.HasIndex(e => e.IpAddress);
            entity.HasIndex(e => e.AnomalyType);
            entity.HasIndex(e => e.AnomalyScore);
            entity.HasIndex(e => e.DetectedAt);
        });

        // Configure CloudResourceEntity
        modelBuilder.Entity<CloudResourceEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.CloudProvider).HasMaxLength(50);
            entity.Property(e => e.Region).HasMaxLength(100);
            entity.Property(e => e.ResourceType).HasMaxLength(100);
            entity.Property(e => e.ResourceId).HasMaxLength(255);
            entity.Property(e => e.PublicIpAddress).HasMaxLength(45);
            entity.Property(e => e.PrivateIpAddress).HasMaxLength(45);
            entity.Property(e => e.ResourceName).HasMaxLength(255);
            entity.Property(e => e.Status).HasMaxLength(50);

            // Indexes
            entity.HasIndex(e => e.CloudProvider);
            entity.HasIndex(e => e.Region);
            entity.HasIndex(e => e.ResourceType);
            entity.HasIndex(e => e.ResourceId);
            entity.HasIndex(e => e.PublicIpAddress);
            entity.HasIndex(e => e.PrivateIpAddress);
            entity.HasIndex(e => e.Status);
            entity.HasIndex(e => e.DiscoveredAt);
        });
    }

    /// <summary>
    /// Configures the database connection when no options are provided.
    /// </summary>
    /// <param name="optionsBuilder">The options builder.</param>
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            // Default to SQLite for development
            var databasePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "AdvancedNetworkDiscovery",
                "NetworkDiscovery.db"
            );

            Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
            optionsBuilder.UseSqlite($"Data Source={databasePath}");
        }
    }
}