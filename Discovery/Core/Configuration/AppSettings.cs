using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace Discovery.Core.Configuration
{
    /// <summary>
    /// Application settings and configuration management
    /// </summary>
    public class AppSettings
    {
        private const string SETTINGS_FILE = "settings.json";
        private static AppSettings? _instance;
        private static readonly object _lock = new();

        /// <summary>
        /// Singleton instance of application settings
        /// </summary>
        public static AppSettings Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        _instance ??= LoadSettings().Result;
                    }
                }
                return _instance;
            }
        }

        // Network scanning settings
        /// <summary>
        /// Gets or sets the network scanning configuration settings.
        /// </summary>
        public NetworkScanSettings ScanSettings { get; set; } = new();
        
        // Display and UI settings
        /// <summary>
        /// Gets or sets the display and user interface settings.
        /// </summary>
        public DisplaySettings Display { get; set; } = new();
        
        // Security and stealth settings
        /// <summary>
        /// Gets or sets the security and stealth configuration settings.
        /// </summary>
        public SecuritySettings Security { get; set; } = new();
        
        // Export and logging settings
        /// <summary>
        /// Gets or sets the export and logging configuration settings.
        /// </summary>
        public ExportSettings Export { get; set; } = new();
        
        // Advanced feature settings
        /// <summary>
        /// Gets or sets the advanced feature configuration settings.
        /// </summary>
        public AdvancedSettings Advanced { get; set; } = new();

        // Performance settings
        /// <summary>
        /// Gets or sets the performance optimization settings.
        /// </summary>
        public PerformanceSettings Performance { get; set; } = new();

        /// <summary>
        /// Network scanning configuration
        /// </summary>
        public class NetworkScanSettings
        {
            /// <summary>
            /// Gets or sets the default timeout for network operations in milliseconds.
            /// </summary>
            public int DefaultTimeout { get; set; } = 2000;
            
            /// <summary>
            /// Gets or sets the maximum number of concurrent connections allowed.
            /// </summary>
            public int MaxConcurrentConnections { get; set; } = 200;
            
            /// <summary>
            /// Gets or sets whether to enable live result display during scanning.
            /// </summary>
            public bool EnableLiveResults { get; set; } = true;
            
            /// <summary>
            /// Gets or sets whether to show progress bars during operations.
            /// </summary>
            public bool EnableProgressBar { get; set; } = true;
            
            /// <summary>
            /// Gets or sets the list of default ports to scan.
            /// </summary>
            public List<int> DefaultPorts { get; set; } = new() { 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900 };
            
            /// <summary>
            /// Gets or sets the maximum network size allowed for scanning.
            /// </summary>
            public int MaxNetworkSize { get; set; } = 65536;
            
            /// <summary>
            /// Gets or sets whether to warn the user before performing large scans.
            /// </summary>
            public bool WarnOnLargeScans { get; set; } = true;
            
            /// <summary>
            /// Gets or sets whether to skip host discovery phase.
            /// </summary>
            public bool SkipHostDiscovery { get; set; } = false;
            
            /// <summary>
            /// Gets or sets the ping timeout in milliseconds.
            /// </summary>
            public int PingTimeout { get; set; } = 1000;
            
            /// <summary>
            /// Gets or sets whether to enable operating system detection.
            /// </summary>
            public bool EnableOsDetection { get; set; } = true;
            
            /// <summary>
            /// Gets or sets whether to enable service detection.
            /// </summary>
            public bool EnableServiceDetection { get; set; } = true;
        }

        /// <summary>
        /// Display and user interface settings
        /// </summary>
        public class DisplaySettings
        {
            public bool UseColors { get; set; } = true;
            public bool ShowBanner { get; set; } = true;
            public bool ShowSecurityWarnings { get; set; } = true;
            public string Theme { get; set; } = "Default";
            public bool EnableAnimations { get; set; } = true;
            public bool ShowDetailedResults { get; set; } = true;
            public int MaxTableRows { get; set; } = 100;
            public bool AutoRefreshResults { get; set; } = false;
            public int RefreshInterval { get; set; } = 5000;
        }

        /// <summary>
        /// Security and stealth configuration
        /// </summary>
        public class SecuritySettings
        {
            public bool EnableStealthMode { get; set; } = false;
            public int StealthDelayMin { get; set; } = 100;
            public int StealthDelayMax { get; set; } = 1000;
            public bool RandomizePortOrder { get; set; } = false;
            public bool RandomizeIpOrder { get; set; } = false;
            public bool EnableDecoyScanning { get; set; } = false;
            public int MaxDecoyHosts { get; set; } = 3;
            public bool EnableHoneypotDetection { get; set; } = true;
            public bool RequireUserConfirmation { get; set; } = true;
            public List<string> TrustedNetworks { get; set; } = new();
            public bool LogSecurityEvents { get; set; } = true;
        }

        /// <summary>
        /// Export and logging settings
        /// </summary>
        public class ExportSettings
        {
            public string DefaultExportFormat { get; set; } = "json";
            public string ExportDirectory { get; set; } = "results";
            public bool AutoExportResults { get; set; } = false;
            public bool IncludeTimestamp { get; set; } = true;
            public bool CompressExports { get; set; } = false;
            public int MaxExportFiles { get; set; } = 100;
            public bool EnableLogging { get; set; } = true;
            public string LogLevel { get; set; } = "Info";
            public string LogDirectory { get; set; } = "logs";
            public int MaxLogFiles { get; set; } = 10;
            public long MaxLogFileSize { get; set; } = 10485760; // 10MB
        }

        /// <summary>
        /// Advanced feature settings
        /// </summary>
        public class AdvancedSettings
        {
            public bool EnableVulnerabilityScanning { get; set; } = true;
            public bool EnableSslCertificateChecks { get; set; } = true;
            public bool EnableBandwidthTesting { get; set; } = true;
            public bool EnableTraceroute { get; set; } = true;
            public bool EnableDnsEnumeration { get; set; } = true;
            public bool EnableNetworkMapping { get; set; } = true;
            public List<string> CustomDnsServers { get; set; } = new() { "8.8.8.8", "1.1.1.1" };
            public bool UseCustomDnsServers { get; set; } = false;
            public Dictionary<string, string> CustomHeaders { get; set; } = new();
            public string UserAgent { get; set; } = "On-Prem-Network-InfraIQ/2.1.0";
        }

        /// <summary>
        /// Performance optimization settings
        /// </summary>
        public class PerformanceSettings
        {
            public bool EnableConnectionPooling { get; set; } = true;
            public bool EnableResultCaching { get; set; } = true;
            public int CacheExpirationMinutes { get; set; } = 30;
            public bool EnableMemoryOptimization { get; set; } = true;
            public int MaxMemoryUsageMB { get; set; } = 512;
            public bool EnableGarbageCollection { get; set; } = true;
            public int GcInterval { get; set; } = 10000;
            public bool EnableParallelProcessing { get; set; } = true;
            public int MaxDegreeOfParallelism { get; set; } = Environment.ProcessorCount;
        }

        /// <summary>
        /// Loads settings from file or creates default settings
        /// </summary>
        public static async Task<AppSettings> LoadSettings()
        {
            try
            {
                if (File.Exists(SETTINGS_FILE))
                {
                    var json = await File.ReadAllTextAsync(SETTINGS_FILE);
                    var settings = JsonSerializer.Deserialize<AppSettings>(json);
                    if (settings != null)
                    {
                        // Validate and fix any invalid settings
                        settings.ValidateSettings();
                        return settings;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not load settings file: {ex.Message}");
            }

            // Return default settings if file doesn't exist or loading failed
            var defaultSettings = new AppSettings();
            defaultSettings.ValidateSettings();
            return defaultSettings;
        }

        /// <summary>
        /// Saves current settings to file
        /// </summary>
        public async Task SaveSettings()
        {
            try
            {
                ValidateSettings();
                
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                
                var json = JsonSerializer.Serialize(this, options);
                await File.WriteAllTextAsync(SETTINGS_FILE, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not save settings: {ex.Message}");
            }
        }

        /// <summary>
        /// Validates and corrects invalid settings
        /// </summary>
        public void ValidateSettings()
        {
            // Validate scan settings
            ScanSettings.DefaultTimeout = Math.Max(100, Math.Min(ScanSettings.DefaultTimeout, 30000));
            ScanSettings.MaxConcurrentConnections = Math.Max(1, Math.Min(ScanSettings.MaxConcurrentConnections, 1000));
            ScanSettings.MaxNetworkSize = Math.Max(1, ScanSettings.MaxNetworkSize);
            ScanSettings.PingTimeout = Math.Max(100, Math.Min(ScanSettings.PingTimeout, 10000));

            // Validate security settings
            Security.StealthDelayMin = Math.Max(0, Security.StealthDelayMin);
            Security.StealthDelayMax = Math.Max(Security.StealthDelayMin, Security.StealthDelayMax);
            Security.MaxDecoyHosts = Math.Max(0, Math.Min(Security.MaxDecoyHosts, 10));

            // Validate display settings
            Display.MaxTableRows = Math.Max(10, Math.Min(Display.MaxTableRows, 10000));
            Display.RefreshInterval = Math.Max(1000, Display.RefreshInterval);

            // Validate export settings
            Export.MaxExportFiles = Math.Max(1, Export.MaxExportFiles);
            Export.MaxLogFiles = Math.Max(1, Export.MaxLogFiles);
            Export.MaxLogFileSize = Math.Max(1024, Export.MaxLogFileSize);

            // Validate performance settings
            Performance.MaxMemoryUsageMB = Math.Max(64, Performance.MaxMemoryUsageMB);
            Performance.MaxDegreeOfParallelism = Math.Max(1, Math.Min(Performance.MaxDegreeOfParallelism, Environment.ProcessorCount * 2));
            Performance.CacheExpirationMinutes = Math.Max(1, Performance.CacheExpirationMinutes);
            Performance.GcInterval = Math.Max(1000, Performance.GcInterval);

            // Ensure directories exist
            if (!string.IsNullOrEmpty(Export.ExportDirectory))
            {
                Directory.CreateDirectory(Export.ExportDirectory);
            }
            if (!string.IsNullOrEmpty(Export.LogDirectory))
            {
                Directory.CreateDirectory(Export.LogDirectory);
            }
        }

        /// <summary>
        /// Resets all settings to default values
        /// </summary>
        public void ResetToDefaults()
        {
            ScanSettings = new NetworkScanSettings();
            Display = new DisplaySettings();
            Security = new SecuritySettings();
            Export = new ExportSettings();
            Advanced = new AdvancedSettings();
            Performance = new PerformanceSettings();
            ValidateSettings();
        }

        /// <summary>
        /// Gets a setting value by path (e.g., "ScanSettings.DefaultTimeout")
        /// </summary>
        public object? GetSetting(string path)
        {
            try
            {
                var parts = path.Split('.');
                if (parts.Length != 2) return null;

                var section = parts[0];
                var property = parts[1];

                var sectionObject = section switch
                {
                    nameof(ScanSettings) => (object)ScanSettings,
                    nameof(Display) => (object)Display,
                    nameof(Security) => (object)Security,
                    nameof(Export) => (object)Export,
                    nameof(Advanced) => (object)Advanced,
                    nameof(Performance) => (object)Performance,
                    _ => (object?)null
                };

                if (sectionObject == null) return null;

                var propertyInfo = sectionObject.GetType().GetProperty(property);
                return propertyInfo?.GetValue(sectionObject);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Sets a setting value by path
        /// </summary>
        public bool SetSetting(string path, object value)
        {
            try
            {
                var parts = path.Split('.');
                if (parts.Length != 2) return false;

                var section = parts[0];
                var property = parts[1];

                var sectionObject = section switch
                {
                    nameof(ScanSettings) => (object)ScanSettings,
                    nameof(Display) => (object)Display,
                    nameof(Security) => (object)Security,
                    nameof(Export) => (object)Export,
                    nameof(Advanced) => (object)Advanced,
                    nameof(Performance) => (object)Performance,
                    _ => (object?)null
                };

                if (sectionObject == null) return false;

                var propertyInfo = sectionObject.GetType().GetProperty(property);
                if (propertyInfo == null || !propertyInfo.CanWrite) return false;

                // Convert value to the correct type
                var convertedValue = Convert.ChangeType(value, propertyInfo.PropertyType);
                propertyInfo.SetValue(sectionObject, convertedValue);
                
                ValidateSettings();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets all available settings with their current values
        /// </summary>
        public Dictionary<string, object> GetAllSettings()
        {
            var settings = new Dictionary<string, object>();

            AddSectionSettings(settings, nameof(ScanSettings), ScanSettings);
            AddSectionSettings(settings, nameof(Display), Display);
            AddSectionSettings(settings, nameof(Security), Security);
            AddSectionSettings(settings, nameof(Export), Export);
            AddSectionSettings(settings, nameof(Advanced), Advanced);
            AddSectionSettings(settings, nameof(Performance), Performance);

            return settings;
        }

        private void AddSectionSettings(Dictionary<string, object> settings, string sectionName, object sectionObject)
        {
            var properties = sectionObject.GetType().GetProperties();
            foreach (var property in properties)
            {
                if (property.CanRead)
                {
                    var value = property.GetValue(sectionObject);
                    if (value != null)
                    {
                        settings[$"{sectionName}.{property.Name}"] = value;
                    }
                }
            }
        }
    }
}