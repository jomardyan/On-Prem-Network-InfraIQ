using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace Discovery.Services.Utilities
{
    /// <summary>
    /// Service for testing network bandwidth by downloading test files
    /// </summary>
    public class BandwidthTester
    {
        private readonly HttpClient _httpClient;
        private readonly string[] _defaultTestUrls = 
        {
            "http://speedtest.ftp.otenet.gr/files/test100k.db",
            "http://speedtest.ftp.otenet.gr/files/test1Mb.db",
            "http://speedtest.ftp.otenet.gr/files/test10Mb.db"
        };

        /// <summary>
        /// Initializes a new instance of the BandwidthTester class
        /// </summary>
        public BandwidthTester()
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
        }

        /// <summary>
        /// Tests bandwidth by downloading files of different sizes
        /// </summary>
        /// <param name="customUrls">Optional custom URLs to test download speed</param>
        /// <returns>A list of test results with download size, time, and speed</returns>
        public async Task<List<BandwidthTestResult>> TestBandwidth(string[]? customUrls = null)
        {
            var results = new List<BandwidthTestResult>();
            var urlsToTest = customUrls?.Length > 0 ? customUrls : _defaultTestUrls;
            
            foreach (var url in urlsToTest)
            {
                try
                {
                    var result = await PerformBandwidthTest(url);
                    results.Add(result);
                    
                    // Wait between tests to prevent throttling
                    await Task.Delay(1000);
                }
                catch (Exception ex)
                {
                    results.Add(new BandwidthTestResult
                    {
                        Url = url,
                        Success = false,
                        ErrorMessage = ex.Message
                    });
                }
            }
            
            return results;
        }

        /// <summary>
        /// Tests bandwidth to a specific endpoint
        /// </summary>
        /// <param name="url">The URL to download for testing</param>
        /// <returns>Test result with download statistics</returns>
        public async Task<BandwidthTestResult> PerformBandwidthTest(string url)
        {
            var result = new BandwidthTestResult
            {
                Url = url,
                StartTime = DateTime.Now
            };
            
            try
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                var response = await _httpClient.GetAsync(url);
                var data = await response.Content.ReadAsByteArrayAsync();
                stopwatch.Stop();
                
                result.Success = true;
                result.EndTime = DateTime.Now;
                result.ElapsedMilliseconds = stopwatch.ElapsedMilliseconds;
                result.DownloadedBytes = data.Length;
                result.CalculateSpeedMetrics();
                
                return result;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.EndTime = DateTime.Now;
                return result;
            }
        }
        
        /// <summary>
        /// Disposes the HTTP client when the service is disposed
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
    
    /// <summary>
    /// Represents the result of a bandwidth test
    /// </summary>
    public class BandwidthTestResult
    {
        /// <summary>
        /// The URL that was tested
        /// </summary>
        public string Url { get; set; } = string.Empty;
        
        /// <summary>
        /// Whether the test was successful
        /// </summary>
        public bool Success { get; set; }
        
        /// <summary>
        /// Error message if the test failed
        /// </summary>
        public string ErrorMessage { get; set; } = string.Empty;
        
        /// <summary>
        /// When the test started
        /// </summary>
        public DateTime StartTime { get; set; }
        
        /// <summary>
        /// When the test ended
        /// </summary>
        public DateTime EndTime { get; set; }
        
        /// <summary>
        /// Time taken for the download in milliseconds
        /// </summary>
        public long ElapsedMilliseconds { get; set; }
        
        /// <summary>
        /// Number of bytes downloaded
        /// </summary>
        public long DownloadedBytes { get; set; }
        
        /// <summary>
        /// Download speed in bytes per second
        /// </summary>
        public double BytesPerSecond { get; private set; }
        
        /// <summary>
        /// Download speed in megabits per second
        /// </summary>
        public double MegabitsPerSecond { get; private set; }
        
        /// <summary>
        /// File size in MB
        /// </summary>
        public double FileSizeMB { get; private set; }
        
        /// <summary>
        /// Calculates speed metrics based on download size and time
        /// </summary>
        public void CalculateSpeedMetrics()
        {
            if (ElapsedMilliseconds <= 0)
                return;
                
            // Calculate bytes per second
            BytesPerSecond = DownloadedBytes / (ElapsedMilliseconds / 1000.0);
            
            // Calculate megabits per second (1 byte = 8 bits, 1 MB = 1,048,576 bytes)
            MegabitsPerSecond = (DownloadedBytes * 8) / (ElapsedMilliseconds / 1000.0) / 1_000_000;
            
            // Calculate file size in MB
            FileSizeMB = DownloadedBytes / 1024.0 / 1024.0;
        }
        
        /// <summary>
        /// Returns a formatted string with the test results
        /// </summary>
        public override string ToString()
        {
            if (!Success)
            {
                return $"Test failed for {Url}: {ErrorMessage}";
            }
            
            return $"Downloaded {FileSizeMB:F2} MB in {ElapsedMilliseconds}ms ({MegabitsPerSecond:F2} Mbps)";
        }
    }
}
