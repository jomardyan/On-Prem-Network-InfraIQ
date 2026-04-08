using Discovery.Tools.Documentation;
using System.CommandLine;

namespace Discovery.Tools;

/// <summary>
/// Documentation generation tool.
/// </summary>
public static class DocumentationTool
{
    /// <summary>
    /// Main entry point for documentation generation.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Exit code.</returns>
    public static async Task<int> RunAsync(string[] args)
    {
        var rootCommand = new RootCommand("On-Prem Network InfraIQ - Documentation Generator")
        {
            new Option<string>("--project-path", "Path to the project directory")
            {
                IsRequired = false
            },
            new Option<string>("--output-path", "Path where documentation will be generated")
            {
                IsRequired = false
            },
            new Option<bool>("--verbose", "Enable verbose output")
            {
                IsRequired = false
            }
        };

        rootCommand.SetHandler(async (string projectPath, string outputPath, bool verbose) =>
        {
            try
            {
                // Default to current directory if not specified
                projectPath = string.IsNullOrEmpty(projectPath) ? Environment.CurrentDirectory : projectPath;
                
                if (verbose)
                {
                    Console.WriteLine($"Project path: {projectPath}");
                    Console.WriteLine($"Output path: {outputPath}");
                }

                var generator = new AutoDocumentationGenerator(projectPath, outputPath);
                await generator.GenerateDocumentationAsync();
                
                Console.WriteLine("🎉 Documentation generation completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error generating documentation: {ex.Message}");
                if (verbose)
                {
                    Console.WriteLine($"Stack trace: {ex.StackTrace}");
                }
                Environment.Exit(1);
            }
        }, 
        new Option<string>("--project-path"), 
        new Option<string>("--output-path"), 
        new Option<bool>("--verbose"));

        return await rootCommand.InvokeAsync(args);
    }

    /// <summary>
    /// Generate documentation with default settings.
    /// </summary>
    /// <param name="projectPath">The project path.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public static async Task GenerateAsync(string? projectPath = null)
    {
        projectPath ??= Environment.CurrentDirectory;
        var generator = new AutoDocumentationGenerator(projectPath);
        await generator.GenerateDocumentationAsync();
    }
}