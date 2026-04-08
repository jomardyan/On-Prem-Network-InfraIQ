using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;
using Discovery.Core.Constants;
using Discovery.Core.Models;
using Discovery.Tools;

namespace Discovery.Display
{
    public class LiveScanDisplay : IDisposable
    {
        private readonly ConcurrentBag<ScanResult> _results;
        private readonly object _displayLock = new object();
        private volatile bool _isDisplaying = false;
        private DateTime _scanStartTime;
        private int _totalHostsToScan = 0;
        private readonly ConcurrentDictionary<string, DateTime> _scannedHosts = new();
        private readonly Timer _refreshTimer;
        private int _displayMode = 0; // 0 = Recent, 1 = All Results, 2 = Summary
        private string _filterText = "";
        private bool _showConsoleInstructions = true;
        private readonly SemaphoreSlim _updateSemaphore = new(1, 1);
        private int _lastDisplayHeight = 0;
        private bool _disposed = false;
        private volatile int _updateCount = 0; // Track number of updates to prevent runaway conditions
        private readonly int _maxUpdates = 10000; // Safety limit

        public LiveScanDisplay(ConcurrentBag<ScanResult> results, int totalHosts = 0)
        {
            _results = results;
            _scanStartTime = DateTime.Now;
            _totalHostsToScan = totalHosts;
            _refreshTimer = new Timer(async _ => await UpdateDisplay(), null, Timeout.Infinite, Timeout.Infinite);
        }

        public void StartLiveDisplay()
        {
            if (_disposed) return;
            
            _isDisplaying = true;
            Console.Clear();
            Console.CursorVisible = false;
            
            // Capture initial console dimensions
            try
            {
                _lastDisplayHeight = Console.WindowHeight;
            }
            catch
            {
                _lastDisplayHeight = 25; // Fallback
            }
            
            // Start refresh timer (increased to 750ms for better stability)
            _refreshTimer.Change(0, 750);

            // Start keyboard input handler in background
            Task.Run(HandleKeyboardInput);
        }

        public void StopLiveDisplay()
        {
            if (_disposed) return;
            
            _isDisplaying = false;
            _refreshTimer.Change(Timeout.Infinite, Timeout.Infinite);
            
            // Wait for any pending updates to complete
            _updateSemaphore.Wait(2000); // Increased timeout
            
            // Perform final update to show complete results
            try
            {
                var finalUpdate = Task.Run(UpdateDisplay);
                finalUpdate.Wait(1000);
            }
            catch
            {
                // Ignore final update errors
            }
            
            Console.CursorVisible = true;
        }

        private async Task HandleKeyboardInput()
        {
            var consecutiveErrors = 0;
            const int maxConsecutiveErrors = 5; // Prevent infinite error loops
            
            while (_isDisplaying && !_disposed && consecutiveErrors < maxConsecutiveErrors)
            {
                try
                {
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);
                        switch (key.Key)
                        {
                            case ConsoleKey.Tab:
                                _displayMode = (_displayMode + 1) % 3;
                                break;
                            case ConsoleKey.F1:
                                _showConsoleInstructions = !_showConsoleInstructions;
                                break;
                            case ConsoleKey.Escape:
                                _filterText = "";
                                break;
                            case ConsoleKey.Q:
                                _isDisplaying = false;
                                return;
                        }
                        
                        // Force immediate update after key press with timeout protection
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2)))
                                {
                                    await UpdateDisplay();
                                }
                            }
                            catch
                            {
                                // Ignore update errors from key press
                            }
                        });
                    }
                    
                    // Reset error counter on successful iteration
                    consecutiveErrors = 0;
                    await Task.Delay(150); // Slightly increased delay to reduce CPU usage
                }
                catch (Exception)
                {
                    consecutiveErrors++;
                    // Handle console access errors gracefully with exponential backoff
                    var delay = Math.Min(1000 * consecutiveErrors, 5000);
                    await Task.Delay(delay);
                }
            }
            
            // If we exit due to too many errors, stop displaying
            if (consecutiveErrors >= maxConsecutiveErrors)
            {
                _isDisplaying = false;
            }
        }

        private async Task UpdateDisplay()
        {
            if (!_isDisplaying || _disposed) return;
            
            // Safety check to prevent runaway updates
            if (Interlocked.Increment(ref _updateCount) > _maxUpdates)
            {
                _isDisplaying = false;
                return;
            }

            // Use semaphore to prevent overlapping updates - increased timeout for better reliability
            if (!await _updateSemaphore.WaitAsync(100))
                return;

            try
            {
                var currentResults = _results.ToList();
                var filteredResults = string.IsNullOrEmpty(_filterText) 
                    ? currentResults 
                    : currentResults.Where(r => r.IpAddress.ToString().Contains(_filterText) || 
                                               r.Service.Contains(_filterText, StringComparison.OrdinalIgnoreCase)).ToList();

                // Use StringBuilder for better performance and reduce console operations
                var displayContent = new System.Text.StringBuilder();
                
                // Build header
                var headerContent = BuildHeaderContent(currentResults);
                displayContent.Append(headerContent);
                
                // Build main content based on display mode
                var mainContent = _displayMode switch
                {
                    0 => BuildRecentResultsContent(filteredResults),
                    1 => BuildAllResultsContent(filteredResults),
                    2 => BuildSummaryContent(currentResults),
                    _ => ""
                };
                displayContent.Append(mainContent);
                
                // Build footer
                var footerContent = BuildFooterContent();
                displayContent.Append(footerContent);
                
                // Single console operation to reduce flicker and improve responsiveness
                lock (_displayLock)
                {
                    try
                    {
                        Console.SetCursorPosition(0, 0);
                        var output = displayContent.ToString();
                        
                        // Ensure output doesn't exceed console height to prevent scrolling issues
                        var lines = output.Split('\n');
                        var maxLines = Math.Min(lines.Length, Console.WindowHeight - 1);
                        var trimmedOutput = string.Join('\n', lines.Take(maxLines));
                        
                        Console.Write(trimmedOutput);
                        
                        // More efficient clearing of remaining lines
                        ClearRemainingLines(maxLines);
                    }
                    catch (Exception)
                    {
                        // Ignore console errors during rapid updates - continue with next refresh
                    }
                }
            }
            catch (Exception)
            {
                // Ignore any errors during display update - continue with next refresh
            }
            finally
            {
                _updateSemaphore.Release();
            }
        }

        private string BuildHeaderContent(List<ScanResult> results)
        {
            var elapsed = DateTime.Now - _scanStartTime;
            var uniqueHosts = results.Select(r => r.IpAddress).Distinct().Count();
            var totalPorts = results.Count;
            var avgPing = results.Where(r => r.PingTime.HasValue).Any() 
                ? results.Where(r => r.PingTime.HasValue).Average(r => r.PingTime!.Value) 
                : 0;
            var vulnerablePorts = results.Count(r => NetworkConstants.VulnerablePorts.ContainsKey(r.Port));
            
            return $"╔══════════════════════════════════════════════════════════════════════════════════════╗\n" +
                   $"║  🔍 Network Discovery Scanner - Live Results                                         ║\n" +
                   $"║  ⏱️ Elapsed: {elapsed:hh\\:mm\\:ss} | 🖥️ Hosts: {uniqueHosts}" +
                   (_totalHostsToScan > 0 ? $"/{_totalHostsToScan}" : "").PadRight(8) + 
                   $" | 🔌 Ports: {totalPorts.ToString().PadRight(5)} | ⚠️ Vuln: {vulnerablePorts.ToString().PadRight(3)} | 📡 Ping: {avgPing:F1}ms".PadRight(20) + " ║\n" +
                   $"╚══════════════════════════════════════════════════════════════════════════════════════╝\n\n";
        }

        private string BuildRecentResultsContent(List<ScanResult> results)
        {
            var recentResults = results.OrderByDescending(r => r.DiscoveredAt ?? DateTime.MinValue).Take(12).ToList();
            
            var content = new System.Text.StringBuilder();
            content.AppendLine("┌─────────────────┬──────┬─────────────────┬─────────┬─────────────┬──────────┐");
            content.AppendLine("│ 🌐 IP Address   │ Port │ ⚙️ Service      │ 📡 Ping │ 💻 OS       │ 🕒 Time  │");
            content.AppendLine("├─────────────────┼──────┼─────────────────┼─────────┼─────────────┼──────────┤");

            foreach (var result in recentResults)
            {
                var ip = result.IpAddress.ToString().PadRight(15);
                var port = result.Port.ToString().PadRight(5);
                var service = (result.Service.Length > 15 ? result.Service.Substring(0, 12) + "..." : result.Service).PadRight(15);
                var ping = (result.PingTime.HasValue ? result.PingTime.Value + "ms" : "-").PadRight(7);
                var os = (result.OperatingSystem.Length > 11 ? result.OperatingSystem.Substring(0, 8) + "..." : result.OperatingSystem).PadRight(11);
                var time = (result.DiscoveredAt ?? DateTime.MinValue).ToString("HH:mm:ss").PadRight(8);
                var vulnIndicator = NetworkConstants.VulnerablePorts.ContainsKey(result.Port) ? "⚠" : " ";
                
                content.AppendLine($"│ {ip} │ {vulnIndicator}{port} │ {service} │ {ping} │ {os} │ {time} │");
            }
            
            content.AppendLine("└─────────────────┴──────┴─────────────────┴─────────┴─────────────┴──────────┘");
            
            if (results.Count > 12)
            {
                content.AppendLine($"... showing {recentResults.Count} of {results.Count} total results");
            }
            
            return content.ToString();
        }

        private string BuildAllResultsContent(List<ScanResult> results)
        {
            var groupedResults = results.GroupBy(r => r.IpAddress).OrderBy(g => g.Key, new IpAddressComparer()).ToList();
            var maxHostsToShow = Math.Min(8, groupedResults.Count);
            
            var content = new System.Text.StringBuilder();
            content.AppendLine("┌──────────────────┬──────────────────────────────────────────────────────────────┐");
            content.AppendLine("│ 🖥️ Host          │ 🔌 Open Ports & Services                                     │");
            content.AppendLine("├──────────────────┼──────────────────────────────────────────────────────────────┤");

            foreach (var group in groupedResults.Take(maxHostsToShow))
            {
                var host = group.Key.ToString().PadRight(16);
                var ports = string.Join(", ", group.Select(r => 
                    NetworkConstants.VulnerablePorts.ContainsKey(r.Port) ? $"⚠{r.Port}" : r.Port.ToString()));
                
                if (ports.Length > 60)
                    ports = ports.Substring(0, 57) + "...";
                    
                ports = ports.PadRight(60);
                
                content.AppendLine($"│ {host} │ {ports} │");
            }
            
            content.AppendLine("└──────────────────┴──────────────────────────────────────────────────────────────┘");
            
            if (groupedResults.Count > maxHostsToShow)
            {
                content.AppendLine($"... showing {maxHostsToShow} of {groupedResults.Count} total hosts");
            }
            
            return content.ToString();
        }

        private string BuildSummaryContent(List<ScanResult> results)
        {
            var content = new System.Text.StringBuilder();
            
            // Summary statistics
            var hostCount = results.Select(r => r.IpAddress).Distinct().Count();
            var portCount = results.Count;
            var vulnCount = results.Count(r => NetworkConstants.VulnerablePorts.ContainsKey(r.Port));
            var serviceStats = results.GroupBy(r => r.Service).OrderByDescending(g => g.Count()).Take(5);
            var osStats = results.Where(r => !string.IsNullOrEmpty(r.OperatingSystem))
                                .GroupBy(r => r.OperatingSystem).OrderByDescending(g => g.Count()).Take(3);
            
            content.AppendLine("╔══════════════════ SCAN SUMMARY ══════════════════╗");
            content.AppendLine($"║ 📊 Total Hosts Discovered: {hostCount.ToString().PadLeft(21)} ║");
            content.AppendLine($"║ 🔌 Total Open Ports: {portCount.ToString().PadLeft(25)} ║");
            content.AppendLine($"║ ⚠️ Vulnerable Services: {vulnCount.ToString().PadLeft(23)} ║");
            content.AppendLine("╠══════════════════════════════════════════════════╣");
            content.AppendLine("║ 🏆 Top Services:                                 ║");
            
            foreach (var service in serviceStats)
            {
                var serviceName = service.Key.Length > 20 ? service.Key.Substring(0, 17) + "..." : service.Key;
                content.AppendLine($"║   • {serviceName.PadRight(20)} ({service.Count().ToString().PadLeft(3)})            ║");
            }
            
            if (osStats.Any())
            {
                content.AppendLine("║ 💻 Operating Systems:                            ║");
                foreach (var os in osStats)
                {
                    var osName = os.Key.Length > 20 ? os.Key.Substring(0, 17) + "..." : os.Key;
                    content.AppendLine($"║   • {osName.PadRight(20)} ({os.Count().ToString().PadLeft(3)})            ║");
                }
            }
            
            content.AppendLine("╚══════════════════════════════════════════════════╝");
            
            return content.ToString();
        }

        private string BuildFooterContent()
        {
            var mode = _displayMode switch
            {
                0 => "Recent Results",
                1 => "All Results",
                2 => "Summary",
                _ => "Unknown"
            };
            
            return $"\n" +
                   $"┌────────────────────────────────────────────────────────────────────────────────────┐\n" +
                   $"│ View: {mode.PadRight(12)} │ TAB: Switch View │ ESC: Clear Filter │ Q: Quit │\n" +
                   $"└────────────────────────────────────────────────────────────────────────────────────┘\n";
        }

        private void ClearRemainingLines(int currentOutputLines = -1)
        {
            try
            {
                var startLine = currentOutputLines > 0 ? currentOutputLines : Console.CursorTop;
                var windowHeight = Console.WindowHeight;
                var windowWidth = Console.WindowWidth;
                
                // Only clear if we have lines to clear and avoid edge cases
                if (startLine < windowHeight - 1 && windowWidth > 0)
                {
                    var clearLine = new string(' ', Math.Min(windowWidth - 1, 120)); // Limit to reasonable width
                    
                    for (int i = startLine; i < windowHeight - 1; i++)
                    {
                        try
                        {
                            Console.SetCursorPosition(0, i);
                            Console.Write(clearLine);
                        }
                        catch
                        {
                            // Stop clearing if we hit an error (e.g., console resized)
                            break;
                        }
                    }
                }
                
                // Return cursor to safe position
                if (currentOutputLines > 0)
                {
                    Console.SetCursorPosition(0, currentOutputLines);
                }
                else
                {
                    Console.SetCursorPosition(0, Math.Min(Console.CursorTop, windowHeight - 2));
                }
            }
            catch (Exception)
            {
                // Ignore all console access errors - this is non-critical cleanup
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            
            _disposed = true;
            StopLiveDisplay();
            
            try
            {
                _refreshTimer?.Dispose();
                _updateSemaphore?.Dispose();
            }
            catch (Exception)
            {
                // Ignore disposal errors
            }
        }
    }
}
