using Microsoft.AspNetCore.Mvc;
using Discovery.Core.Models;
using Discovery.Web.Models;
using Discovery.Services.Scanning;
using Discovery.Services.Security;
using Discovery.Services.Data;
using Discovery.Core.Constants;
using Discovery.Core.Utilities;
using Discovery.Web.Hubs;
using Microsoft.AspNetCore.SignalR;
using System.Net;
using System.Collections.Concurrent;

namespace Discovery.Web.Controllers;

/// <summary>
/// Enhanced API controller for advanced network scanning operations with real-time updates
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class NetworkScanController : ControllerBase
{
    private readonly ILogger<NetworkScanController> _logger;
    private readonly AdvancedPortScanner _advancedPortScanner;
    private readonly PortScanner _portScanner;
    private readonly VulnerabilityScanner _vulnerabilityScanner;
    private readonly IPv6Scanner _ipv6Scanner;
    private readonly DatabaseService _databaseService;
    private readonly IHubContext<ScanHub> _hubContext;
    
    // Track active scans
    private static readonly ConcurrentDictionary<string, CancellationTokenSource> _activeScans = new();
    private static readonly ConcurrentDictionary<string, ScanProgressUpdate> _scanProgress = new();

    public NetworkScanController(
        ILogger<NetworkScanController> logger,
        AdvancedPortScanner advancedPortScanner,
        PortScanner portScanner,
        VulnerabilityScanner vulnerabilityScanner,
        IPv6Scanner ipv6Scanner,
        DatabaseService databaseService,
        IHubContext<ScanHub> hubContext)
    {
        _logger = logger;
        _advancedPortScanner = advancedPortScanner;
        _portScanner = portScanner;
        _vulnerabilityScanner = vulnerabilityScanner;
        _ipv6Scanner = ipv6Scanner;
        _databaseService = databaseService;
        _hubContext = hubContext;
    }

    /// <summary>
    /// Scan a single IP address and return port scan results
    /// </summary>
    [HttpPost("scan-ip")]
    public async Task<IActionResult> ScanIpAddress([FromBody] ScanIpRequest request)
    {
        if (!IPAddress.TryParse(request.IpAddress, out _))
        {
            return BadRequest(new { error = "Invalid IP address format" });
        }

        var ports = (request.Ports ?? [22, 80, 443]).ToList();
        var timeout = request.TimeoutMs ?? 5000;
        var openPorts = await ScanPortsAsync(request.IpAddress, ports, timeout, CancellationToken.None);

        var results = ports.Select(p => new PortScanResult
        {
            IpAddress = request.IpAddress,
            Port = p,
            IsOpen = openPorts.Contains(p),
            ServiceName = GetServiceName(p),
            ScanTime = DateTime.UtcNow
        }).ToList();

        return Ok(results);
    }

    /// <summary>
    /// Perform an advanced synchronous scan and return results directly
    /// </summary>
    [HttpPost("advanced-scan")]
    public async Task<IActionResult> PerformAdvancedScan([FromBody] AdvancedScanRequest request)
    {
        if (string.IsNullOrEmpty(request.Target))
        {
            return BadRequest(new { error = "Target is required" });
        }

        var sessionId = request.ScanId ?? Guid.NewGuid().ToString();
        var ports = (request.Ports ?? [22, 80, 443, 8080]).ToList();
        var openPorts = await ScanPortsAsync(request.Target, ports, request.Timeout, CancellationToken.None);

        var scanResults = openPorts.Select(p => new PortScanResult
        {
            IpAddress = request.Target,
            Port = p,
            IsOpen = true,
            ServiceName = GetServiceName(p),
            ScanTime = DateTime.UtcNow
        }).ToList();

        return Ok(new { sessionId, scanResults });
    }

    /// <summary>
    /// Scan a network range (CIDR) and return a session for tracking
    /// </summary>
    [HttpPost("scan-network")]
    public async Task<IActionResult> ScanNetwork([FromBody] ScanNetworkRequest request)
    {
        if (string.IsNullOrEmpty(request.NetworkRange))
        {
            return BadRequest(new { error = "NetworkRange is required" });
        }

        var sessionId = Guid.NewGuid().ToString();
        var ports = (request.Ports ?? [22, 80, 443]).ToList();
        var timeout = request.TimeoutMs ?? 5000;

        // Fire-and-forget background scan
        _ = Task.Run(async () =>
        {
            try
            {
                await ScanPortsAsync(request.NetworkRange, ports, timeout, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Background network scan failed for range {NetworkRange}", request.NetworkRange);
            }
        });

        return Ok(new { sessionId, networkRange = request.NetworkRange, status = "Scanning" });
    }

    /// <summary>
    /// Scan an IPv6 address
    /// </summary>
    [HttpPost("scan-ipv6")]
    public async Task<IActionResult> ScanIPv6([FromBody] IPv6ScanRequest request)
    {
        if (!IPAddress.TryParse(request.IPv6Address, out _))
        {
            return BadRequest(new { error = "Invalid IPv6 address format" });
        }

        var ports = (request.Ports ?? [22, 80, 443]).ToList();
        var timeout = request.TimeoutMs ?? 5000;
        var openPorts = await ScanPortsAsync(request.IPv6Address, ports, timeout, CancellationToken.None);

        return Ok(new
        {
            target = request.IPv6Address,
            openPorts = openPorts,
            discoverNeighbors = request.DiscoverNeighbors,
            scanTime = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Start an advanced network scan with real-time updates
    /// </summary>
    [HttpPost("advanced")]
    public async Task<IActionResult> StartAdvancedScan([FromBody] AdvancedScanRequest request)
    {
        try
        {
            // Ensure ScanId is never null
            request.ScanId ??= Guid.NewGuid().ToString();

            // Validate request
            if (string.IsNullOrEmpty(request.Target))
            {
                return BadRequest(new { error = "Target is required" });
            }

            // Create cancellation token for this scan
            var cancellationTokenSource = new CancellationTokenSource();
            _activeScans.TryAdd(request.ScanId, cancellationTokenSource);

            // Initialize progress tracking
            var progress = new ScanProgressUpdate
            {
                ScanId = request.ScanId,
                StartTime = DateTime.UtcNow,
                CurrentStage = "Initializing",
                StatusMessage = "Preparing scan configuration..."
            };
            
            _scanProgress.TryAdd(request.ScanId, progress);

            // Start scan in background
            _ = Task.Run(async () => await ExecuteAdvancedScanAsync(request, cancellationTokenSource.Token));

            return Ok(new { scanId = request.ScanId, message = "Scan started successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start advanced scan");
            return StatusCode(500, new { error = "Failed to start scan", details = ex.Message });
        }
    }

    /// <summary>
    /// Stop a running scan
    /// </summary>
    [HttpPost("stop/{scanId}")]
    public async Task<IActionResult> StopScan(string scanId)
    {
        try
        {
            if (_activeScans.TryRemove(scanId, out var cancellationTokenSource))
            {
                cancellationTokenSource.Cancel();
                
                // Update progress
                if (_scanProgress.TryGetValue(scanId, out var progress))
                {
                    progress.StatusMessage = "Scan stopped by user";
                    progress.IsCompleted = true;
                    await _hubContext.Clients.Group(scanId).SendAsync("ReceiveScanProgress", progress);
                }

                _logger.LogInformation("Scan {ScanId} stopped by user", scanId);
                return Ok(new { message = "Scan stopped successfully" });
            }

            return NotFound(new { error = "Scan not found or already completed" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to stop scan {ScanId}", scanId);
            return StatusCode(500, new { error = "Failed to stop scan" });
        }
    }

    /// <summary>
    /// Get scan progress
    /// </summary>
    [HttpGet("progress/{scanId}")]
    public IActionResult GetScanProgress(string scanId)
    {
        if (_scanProgress.TryGetValue(scanId, out var progress))
        {
            return Ok(progress);
        }

        return NotFound(new { error = "Scan not found" });
    }

    /// <summary>
    /// Get all active scans
    /// </summary>
    [HttpGet("active")]
    public IActionResult GetActiveScans()
    {
        var activeScans = _scanProgress.Values
            .Where(p => !p.IsCompleted)
            .Select(p => new
            {
                p.ScanId,
                p.PercentComplete,
                p.CurrentStage,
                p.StartTime,
                p.HostsScanned,
                p.HostsDiscovered
            })
            .ToList();

        return Ok(activeScans);
    }

    /// <summary>
    /// Get system status
    /// </summary>
    [HttpGet("status")]
    public IActionResult GetStatus()
    {
        return Ok(new
        {
            Status = "Online",
            ActiveScans = _activeScans.Count,
            TotalSessionsTracked = _scanProgress.Count,
            Timestamp = DateTime.UtcNow,
            Version = "2.0",
            Features = new[] { "RealTime", "IPv6", "Vulnerabilities", "AdvancedScanning" }
        });
    }

    private async Task ExecuteAdvancedScanAsync(AdvancedScanRequest request, CancellationToken cancellationToken)
    {
        var progress = _scanProgress[request.ScanId];
        
        try
        {
            // Parse targets
            var targets = await ParseTargetsAsync(request.Target);
            progress.TotalHosts = targets.Count;
            progress.CurrentStage = "Target Discovery";
            progress.StatusMessage = $"Found {targets.Count} targets to scan";
            
            await _hubContext.Clients.Group(request.ScanId).SendAsync("ReceiveScanProgress", progress, cancellationToken);

            var scanTasks = targets.Select(async target =>
            {
                try
                {
                    await ScanTargetAsync(target, request, progress, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    _logger.LogInformation("Scan cancelled for target {Target}", target);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error scanning target {Target}", target);
                }
            });

            // Execute scans with concurrency limit
            var concurrencyLimit = Math.Min(request.MaxConcurrency, 100);
            var semaphore = new SemaphoreSlim(concurrencyLimit);
            
            var limitedTasks = scanTasks.Select(async task =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    await task;
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(limitedTasks);

            // Complete scan
            progress.IsCompleted = true;
            progress.PercentComplete = 100;
            progress.CurrentStage = "Completed";
            progress.StatusMessage = $"Scan completed. Found {progress.HostsDiscovered} hosts, {progress.OpenPorts} open ports";
            
            await _hubContext.Clients.Group(request.ScanId).SendAsync("ReceiveScanProgress", progress, cancellationToken);

        }
        catch (OperationCanceledException)
        {
            progress.StatusMessage = "Scan cancelled";
            progress.IsCompleted = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Advanced scan failed for scan {ScanId}", request.ScanId);
            progress.HasErrors = true;
            progress.ErrorMessage = ex.Message;
            progress.IsCompleted = true;
            
            await _hubContext.Clients.Group(request.ScanId).SendAsync("ReceiveScanProgress", progress);
        }
        finally
        {
            // Cleanup
            _activeScans.TryRemove(request.ScanId, out var _);
            
            // Keep progress for a while for status queries
            _ = Task.Delay(TimeSpan.FromMinutes(30)).ContinueWith(_ =>
            {
                _scanProgress.TryRemove(request.ScanId, out var _);
            });
        }
    }

    private async Task ScanTargetAsync(string target, AdvancedScanRequest request, ScanProgressUpdate progress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            // Perform ping test first
            if (await IsHostAliveAsync(target, cancellationToken))
            {
                progress.HostsDiscovered++;

                string? hostname = null;
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(target);
                    hostname = hostEntry.HostName;
                }
                catch { /* Ignore hostname resolution errors */ }

                // Port scanning
                var ports = request.Ports ?? [22, 80, 443, 21, 23, 25, 53, 110, 143, 993, 995];
                var openPorts = await ScanPortsAsync(target, ports, request.Timeout, cancellationToken);
                
                foreach (var port in openPorts)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var portResult = new PortScanResult
                    {
                        IpAddress = target,
                        Hostname = hostname,
                        Port = port,
                        IsOpen = true,
                        ServiceName = GetServiceName(port),
                        ScanTime = DateTime.UtcNow
                    };

                    // Service detection
                    if (request.EnableServiceDetection)
                    {
                        try
                        {
                            var serviceInfo = await DetectServiceAsync(target, port, cancellationToken);
                            portResult.ServiceName = serviceInfo.Name ?? portResult.ServiceName;
                            portResult.ServiceVersion = serviceInfo.Version;
                        }
                        catch { /* Ignore service detection errors */ }
                    }

                    // Vulnerability scanning
                    if (request.EnableVulnerabilityScanning)
                    {
                        try
                        {
                            var vulnerabilities = await ScanVulnerabilitiesAsync(target, port, portResult.ServiceName, cancellationToken);
                            if (vulnerabilities.Any())
                            {
                                portResult.IsVulnerable = true;
                                portResult.VulnerabilityCount = vulnerabilities.Count;
                                progress.VulnerabilitiesFound++;

                                // Send vulnerability alerts
                                foreach (var vuln in vulnerabilities)
                                {
                                    var alert = new VulnerabilityAlert
                                    {
                                        ScanId = request.ScanId,
                                        Host = target,
                                        Port = port,
                                        Title = vuln.Title,
                                        Description = vuln.Description,
                                        Severity = MapSeverity(vuln.Severity),
                                        ServiceName = portResult.ServiceName,
                                        ServiceVersion = portResult.ServiceVersion
                                    };

                                    await _hubContext.Clients.Group(request.ScanId).SendAsync("ReceiveVulnerabilityAlert", alert, cancellationToken);
                                }
                            }
                        }
                        catch { /* Ignore vulnerability scanning errors */ }
                    }

                    progress.OpenPorts++;

                    // Send real-time update
                    await _hubContext.Clients.Group(request.ScanId).SendAsync("ReceiveScanUpdate", portResult, cancellationToken);
                }
            }

            progress.HostsScanned++;
            progress.PercentComplete = Math.Min(99, (int)(progress.HostsScanned * 100.0 / progress.TotalHosts));
            progress.LastUpdate = DateTime.UtcNow;
            
            // Calculate scan speed
            var elapsed = DateTime.UtcNow - progress.StartTime;
            if (elapsed.TotalSeconds > 0)
            {
                progress.ScanSpeed = progress.HostsScanned / elapsed.TotalSeconds;
                
                // Estimate time remaining
                if (progress.ScanSpeed > 0)
                {
                    var remaining = (progress.TotalHosts - progress.HostsScanned) / progress.ScanSpeed;
                    progress.EstimatedTimeRemaining = TimeSpan.FromSeconds(remaining);
                }
            }

            // Send progress update every few hosts
            if (progress.HostsScanned % 5 == 0 || progress.HostsScanned == progress.TotalHosts)
            {
                await _hubContext.Clients.Group(request.ScanId).SendAsync("ReceiveScanProgress", progress, cancellationToken);
            }

        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error scanning target {Target}", target);
        }
    }

    private async Task<List<string>> ParseTargetsAsync(string targetInput)
    {
        var targets = new List<string>();
        var parts = targetInput.Split(',', StringSplitOptions.RemoveEmptyEntries);

        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            
            if (trimmed.Contains('/'))
            {
                // CIDR notation - simplified expansion
                targets.Add(trimmed);
            }
            else if (trimmed.Contains('-'))
            {
                // IP range - simplified expansion
                targets.Add(trimmed);
            }
            else
            {
                // Single IP or hostname
                targets.Add(trimmed);
            }
        }

        return targets.Distinct().ToList();
    }

    private async Task<bool> IsHostAliveAsync(string host, CancellationToken cancellationToken)
    {
        try
        {
            using var ping = new System.Net.NetworkInformation.Ping();
            var result = await ping.SendPingAsync(host, 3000);
            return result.Status == System.Net.NetworkInformation.IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }

    private async Task<List<int>> ScanPortsAsync(string host, List<int> ports, int timeout, CancellationToken cancellationToken)
    {
        var openPorts = new List<int>();
        var tasks = ports.Select(async port =>
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                
                if (await Task.WhenAny(connectTask, Task.Delay(timeout, cancellationToken)) == connectTask)
                {
                    if (client.Connected)
                    {
                        lock (openPorts) openPorts.Add(port);
                    }
                }
            }
            catch { /* Port is closed or filtered */ }
        });

        await Task.WhenAll(tasks);
        return openPorts;
    }

    private async Task<ServiceInfo> DetectServiceAsync(string host, int port, CancellationToken cancellationToken)
    {
        var serviceInfo = new ServiceInfo { Name = GetServiceName(port) };
        
        try
        {
            using var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync(host, port);
            
            if (client.Connected)
            {
                using var stream = client.GetStream();
                var buffer = new byte[1024];
                
                if (stream.CanRead)
                {
                    var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    if (bytesRead > 0)
                    {
                        var banner = System.Text.Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        serviceInfo.Version = ExtractVersionFromBanner(banner);
                    }
                }
            }
        }
        catch { /* Ignore service detection errors */ }

        return serviceInfo;
    }

    private async Task<List<VulnerabilityInfo>> ScanVulnerabilitiesAsync(string host, int port, string? serviceName, CancellationToken cancellationToken)
    {
        try
        {
            var vulnerabilities = await _vulnerabilityScanner.ScanHostAsync(host);
            return vulnerabilities.Select(v => new VulnerabilityInfo
            {
                Title = v.Name ?? "Unknown Vulnerability",
                Description = v.Description ?? "No description available",
                Severity = v.Severity.ToString()
            }).ToList();
        }
        catch
        {
            return new List<VulnerabilityInfo>();
        }
    }

    private static string GetServiceName(int port)
    {
        if (NetworkConstants.PopularPorts.TryGetValue(port, out var serviceName))
        {
            return serviceName;
        }
        return "Unknown";
    }

    private static string? ExtractVersionFromBanner(string banner)
    {
        var lines = banner.Split('\n', '\r');
        foreach (var line in lines)
        {
            if (line.Contains("Server:") || line.Contains("version", StringComparison.OrdinalIgnoreCase))
            {
                return line.Trim();
            }
        }
        return null;
    }

    private static Discovery.Web.Models.VulnerabilitySeverity MapSeverity(string severity)
    {
        return severity?.ToLower() switch
        {
            "critical" => Discovery.Web.Models.VulnerabilitySeverity.Critical,
            "high" => Discovery.Web.Models.VulnerabilitySeverity.High,
            "medium" => Discovery.Web.Models.VulnerabilitySeverity.Medium,
            "low" => Discovery.Web.Models.VulnerabilitySeverity.Low,
            _ => Discovery.Web.Models.VulnerabilitySeverity.Info
        };
    }

    // Helper classes
    private class ServiceInfo
    {
        public string? Name { get; set; }
        public string? Version { get; set; }
    }

    private class VulnerabilityInfo
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
    }
}
