using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Text.Json;

namespace Discovery.Core.Utilities
{
    /// <summary>
    /// Manages automatic versioning and git tagging for the application
    /// </summary>
    public static class VersionManager
    {
        private const string VERSION_FILE = "version.json";
        
        /// <summary>
        /// Represents comprehensive application data including version and metadata
        /// </summary>
        public class VersionInfo
        {
            public int Major { get; set; } = 1;
            public int Minor { get; set; } = 0;
            public int Patch { get; set; } = 0;
            public string? PreRelease { get; set; }
            public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
            public string? LastCommitHash { get; set; }
            public int BuildNumber { get; set; } = 0;
            public string? ReleaseDate { get; set; }
            public string? Tag { get; set; }
            public string? ProductName { get; set; }
            public string? Description { get; set; }
            public string? Copyright { get; set; }
            public string? Authors { get; set; }
            public List<string> Features { get; set; } = new();

            public string ToVersionString()
            {
                var version = $"{Major}.{Minor}.{Patch}";
                if (!string.IsNullOrEmpty(PreRelease))
                {
                    version += $"-{PreRelease}";
                }
                return version;
            }

            public string ToFullVersionString()
            {
                var version = ToVersionString();
                if (BuildNumber > 0)
                {
                    version += $".{BuildNumber}";
                }
                return version;
            }
        }

        /// <summary>
        /// Version increment type
        /// </summary>
        public enum VersionIncrement
        {
            Patch,
            Minor,
            Major
        }

        /// <summary>
        /// Gets the current version from assembly or version file
        /// </summary>
        public static VersionInfo GetCurrentVersion()
        {
            try
            {
                // Try to load from version file first
                if (File.Exists(VERSION_FILE))
                {
                    var json = File.ReadAllText(VERSION_FILE);
                    var versionInfo = JsonSerializer.Deserialize<VersionInfo>(json);
                    if (versionInfo != null)
                    {
                        return versionInfo;
                    }
                }

                // Fallback to assembly version
                var assembly = Assembly.GetExecutingAssembly();
                var version = assembly.GetName().Version;
                
                return new VersionInfo
                {
                    Major = version?.Major ?? 1,
                    Minor = version?.Minor ?? 0,
                    Patch = version?.Build ?? 0,
                    LastUpdated = DateTime.UtcNow
                };
            }
            catch
            {
                // Return default version if all fails
                return new VersionInfo();
            }
        }

        /// <summary>
        /// Increments the version and saves to file
        /// </summary>
        public static async Task<VersionInfo> IncrementVersion(VersionIncrement increment, string? preRelease = null)
        {
            var currentVersion = GetCurrentVersion();
            
            switch (increment)
            {
                case VersionIncrement.Major:
                    currentVersion.Major++;
                    currentVersion.Minor = 0;
                    currentVersion.Patch = 0;
                    break;
                case VersionIncrement.Minor:
                    currentVersion.Minor++;
                    currentVersion.Patch = 0;
                    break;
                case VersionIncrement.Patch:
                    currentVersion.Patch++;
                    break;
            }

            currentVersion.BuildNumber++;
            currentVersion.PreRelease = preRelease;
            currentVersion.LastUpdated = DateTime.UtcNow;
            currentVersion.LastCommitHash = await GetCurrentCommitHash();

            await SaveVersionToFile(currentVersion);
            return currentVersion;
        }

        /// <summary>
        /// Saves version information to file
        /// </summary>
        public static async Task SaveVersionToFile(VersionInfo version)
        {
            try
            {
                var json = JsonSerializer.Serialize(version, new JsonSerializerOptions 
                { 
                    WriteIndented = true 
                });
                await File.WriteAllTextAsync(VERSION_FILE, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not save version file: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates the project file with new version
        /// </summary>
        public static async Task UpdateProjectVersion(VersionInfo version)
        {
            try
            {
                const string projectFile = "Discovery.csproj";
                if (!File.Exists(projectFile))
                {
                    Console.WriteLine($"Warning: Project file {projectFile} not found");
                    return;
                }

                var content = await File.ReadAllTextAsync(projectFile);
                
                // Update version in csproj file
                var versionString = version.ToVersionString();
                
                // Simple regex replacement - could be improved with XML parsing
                content = System.Text.RegularExpressions.Regex.Replace(
                    content,
                    @"<Version>.*?</Version>",
                    $"<Version>{versionString}</Version>",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase
                );

                await File.WriteAllTextAsync(projectFile, content);
                Console.WriteLine($"Updated project version to {versionString}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not update project file: {ex.Message}");
            }
        }

        /// <summary>
        /// Creates a git tag for the current version
        /// </summary>
        public static async Task<bool> CreateGitTag(VersionInfo version, bool push = false)
        {
            try
            {
                var tagName = $"v{version.ToVersionString()}";
                var tagMessage = $"Release {version.ToFullVersionString()} - {DateTime.Now:yyyy-MM-dd}";

                // Create the tag
                var tagResult = await RunGitCommand($"tag -a {tagName} -m \"{tagMessage}\"");
                if (!tagResult.Success)
                {
                    Console.WriteLine($"Warning: Could not create git tag: {tagResult.Error}");
                    return false;
                }

                Console.WriteLine($"Created git tag: {tagName}");

                // Push the tag if requested
                if (push)
                {
                    var pushResult = await RunGitCommand($"push origin {tagName}");
                    if (pushResult.Success)
                    {
                        Console.WriteLine($"Pushed tag {tagName} to origin");
                    }
                    else
                    {
                        Console.WriteLine($"Warning: Could not push tag: {pushResult.Error}");
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating git tag: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets the current git commit hash
        /// </summary>
        public static async Task<string?> GetCurrentCommitHash()
        {
            try
            {
                var result = await RunGitCommand("rev-parse HEAD");
                return result.Success ? result.Output?.Trim() : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Checks if there are uncommitted changes
        /// </summary>
        public static async Task<bool> HasUncommittedChanges()
        {
            try
            {
                var result = await RunGitCommand("status --porcelain");
                return !string.IsNullOrWhiteSpace(result.Output);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Performs automatic version increment and tagging workflow
        /// </summary>
        public static async Task<VersionInfo?> AutoVersionWorkflow(VersionIncrement increment = VersionIncrement.Patch, bool createTag = true, bool pushTag = false)
        {
            try
            {
                Console.WriteLine("🔄 Starting automatic versioning workflow...");

                // Check for uncommitted changes
                if (await HasUncommittedChanges())
                {
                    Console.WriteLine("⚠️  Warning: Uncommitted changes detected. Consider committing first.");
                }

                // Increment version
                var newVersion = await IncrementVersion(increment);
                Console.WriteLine($"📈 Version incremented to {newVersion.ToFullVersionString()}");

                // Update project file
                await UpdateProjectVersion(newVersion);

                // Create git tag
                if (createTag)
                {
                    var tagCreated = await CreateGitTag(newVersion, pushTag);
                    if (!tagCreated)
                    {
                        Console.WriteLine("⚠️  Git tag creation failed, but version was still incremented");
                    }
                }

                Console.WriteLine($"✅ Versioning workflow completed successfully!");
                return newVersion;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Versioning workflow failed: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Helper method to run git commands
        /// </summary>
        private static async Task<(bool Success, string? Output, string? Error)> RunGitCommand(string arguments)
        {
            try
            {
                using var process = new Process();
                process.StartInfo = new ProcessStartInfo
                {
                    FileName = "git",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                process.Start();
                
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();
                
                await process.WaitForExitAsync();
                
                var output = await outputTask;
                var error = await errorTask;

                return (process.ExitCode == 0, output, error);
            }
            catch (Exception ex)
            {
                return (false, null, ex.Message);
            }
        }

        /// <summary>
        /// Gets version display string for the application
        /// </summary>
        public static string GetVersionDisplayString()
        {
            var version = GetCurrentVersion();
            var commitHash = version.LastCommitHash;
            
            var versionString = version.ToFullVersionString();
            
            if (!string.IsNullOrEmpty(commitHash))
            {
                versionString += $" ({commitHash[..Math.Min(7, commitHash.Length)]})";
            }
            
            return versionString;
        }

        /// <summary>
        /// Gets detailed version information for display
        /// </summary>
        public static string GetDetailedVersionInfo()
        {
            var version = GetCurrentVersion();
            
            return $@"Version: {version.ToFullVersionString()}
Build Date: {version.LastUpdated:yyyy-MM-dd HH:mm:ss} UTC
Commit: {version.LastCommitHash?[..Math.Min(10, version.LastCommitHash?.Length ?? 0)] ?? "Unknown"}
Build Number: {version.BuildNumber}";
        }

        /// <summary>
        /// Gets the current version string (e.g., "2.1.0")
        /// </summary>
        public static string GetVersionString()
        {
            return GetCurrentVersion().ToVersionString();
        }

        /// <summary>
        /// Gets the API version string with 'v' prefix (e.g., "v2.1.0")
        /// </summary>
        public static string GetApiVersionString()
        {
            return $"v{GetVersionString()}";
        }

        /// <summary>
        /// Gets the product name
        /// </summary>
        public static string GetProductName()
        {
            return GetCurrentVersion().ProductName ?? "On-Prem Network InfraIQ";
        }

        /// <summary>
        /// Gets the product description
        /// </summary>
        public static string GetProductDescription()
        {
            return GetCurrentVersion().Description ?? "Enterprise-grade network discovery and security assessment platform";
        }

        /// <summary>
        /// Gets the copyright notice
        /// </summary>
        public static string GetCopyright()
        {
            return GetCurrentVersion().Copyright ?? $"Copyright © {DateTime.Now.Year}";
        }

        /// <summary>
        /// Gets the authors information
        /// </summary>
        public static string GetAuthors()
        {
            return GetCurrentVersion().Authors ?? "On-Prem Network InfraIQ Team";
        }

        /// <summary>
        /// Gets the release tag
        /// </summary>
        public static string GetReleaseTag()
        {
            return GetCurrentVersion().Tag ?? $"v{GetVersionString()}";
        }

        /// <summary>
        /// Gets the release date
        /// </summary>
        public static string GetReleaseDate()
        {
            var version = GetCurrentVersion();
            return version.ReleaseDate ?? version.LastUpdated.ToString("yyyy-MM-dd");
        }

        /// <summary>
        /// Gets comprehensive app data for API status endpoints
        /// </summary>
        public static object GetAppDataForApi()
        {
            var version = GetCurrentVersion();
            return new
            {
                Name = GetProductName(),
                Version = GetVersionString(),
                ApiVersion = GetApiVersionString(),
                Description = GetProductDescription(),
                Authors = GetAuthors(),
                Copyright = GetCopyright(),
                ReleaseDate = GetReleaseDate(),
                Tag = GetReleaseTag(),
                BuildNumber = version.BuildNumber,
                LastUpdated = version.LastUpdated,
                CommitHash = version.LastCommitHash,
                Features = version.Features
            };
        }
    }
}