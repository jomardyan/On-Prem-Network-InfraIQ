using System.Collections.Generic;
using Discovery.Core.Models;

namespace Discovery.Core.Interfaces
{
    /// <summary>
    /// Interface for exporting scan results to different formats
    /// </summary>
    public interface IExporter
    {
        /// <summary>
        /// Exports scan results to a specific file format
        /// </summary>
        /// <param name="results">The scan results to export</param>
        /// <param name="filePath">The path where to save the exported file</param>
        /// <param name="options">Additional export options if needed</param>
        /// <returns>True if the export was successful, otherwise false</returns>
        bool Export(List<ScanResult> results, string filePath, Dictionary<string, object>? options = null);
        
        /// <summary>
        /// Gets the supported file extensions for this exporter
        /// </summary>
        string[] SupportedExtensions { get; }
        
        /// <summary>
        /// Gets a user-friendly description of the export format
        /// </summary>
        string Description { get; }
    }
}
