using Microsoft.AspNetCore.SignalR;
using System;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Security.Claims;
using Discovery.Web.Models;

namespace Discovery.Web.Hubs
{
    /// <summary>
    /// Enhanced SignalR hub for real-time scan updates with advanced features
    /// </summary>
    public class ScanHub : Hub
    {
        private readonly ILogger<ScanHub> _logger;
        private static readonly ConcurrentDictionary<string, ScanSession> _activeSessions = new();
        private static readonly ConcurrentDictionary<string, UserConnection> _userConnections = new();

        public ScanHub(ILogger<ScanHub> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Send a scan update to all clients in a scan group
        /// </summary>
        public async Task SendScanUpdate(string scanId, object update)
        {
            await Clients.Group(scanId).SendAsync("ReceiveScanUpdate", update);
            
            // Update session statistics
            if (_activeSessions.TryGetValue(scanId, out var session))
            {
                session.LastActivity = DateTime.UtcNow;
                session.UpdateCount++;
            }
        }

        /// <summary>
        /// Send scan progress update with detailed metrics
        /// </summary>
        public async Task SendScanProgress(string scanId, ScanProgressUpdate progress)
        {
            await Clients.Group(scanId).SendAsync("ReceiveScanProgress", progress);
            _logger.LogDebug("Scan progress update sent for scan {ScanId}: {Progress}%", scanId, progress.PercentComplete);
        }

        /// <summary>
        /// Send vulnerability alert to specific scan group
        /// </summary>
        public async Task SendVulnerabilityAlert(string scanId, VulnerabilityAlert alert)
        {
            await Clients.Group(scanId).SendAsync("ReceiveVulnerabilityAlert", alert);
            _logger.LogWarning("Vulnerability alert sent for scan {ScanId}: {Severity} - {Title}", 
                scanId, alert.Severity, alert.Title);
        }

        /// <summary>
        /// Send system notification to all connected clients
        /// </summary>
        public async Task SendSystemNotification(SystemNotification notification)
        {
            await Clients.All.SendAsync("ReceiveSystemNotification", notification);
        }

        /// <summary>
        /// Join a specific scan group with user authentication
        /// </summary>
        public async Task JoinScanGroup(string scanId, string? userName = null)
        {
            try
            {
                if (string.IsNullOrEmpty(scanId))
                {
                    await Clients.Caller.SendAsync("Error", "Invalid scan ID");
                    return;
                }

                await Groups.AddToGroupAsync(Context.ConnectionId, scanId);
                
                // Track user connection
                var userConnection = new UserConnection
                {
                    ConnectionId = Context.ConnectionId,
                    ScanId = scanId,
                    UserName = userName ?? "Anonymous",
                    ConnectedAt = DateTime.UtcNow,
                    UserAgent = Context.GetHttpContext()?.Request.Headers["User-Agent"].ToString()
                };
                
                _userConnections.TryAdd(Context.ConnectionId, userConnection);

                // Update or create session
                _activeSessions.AddOrUpdate(scanId, 
                    new ScanSession 
                    { 
                        ScanId = scanId, 
                        ConnectedUsers = 1, 
                        StartTime = DateTime.UtcNow,
                        LastActivity = DateTime.UtcNow
                    },
                    (key, existing) => 
                    {
                        existing.ConnectedUsers++;
                        existing.LastActivity = DateTime.UtcNow;
                        return existing;
                    });

                await Clients.Caller.SendAsync("JoinedScanGroup", scanId);
                await Clients.OthersInGroup(scanId).SendAsync("UserJoined", userConnection);

                _logger.LogInformation("User {UserName} joined scan group {ScanId}", userName, scanId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error joining scan group {ScanId}", scanId);
                await Clients.Caller.SendAsync("Error", "Failed to join scan group");
            }
        }

        /// <summary>
        /// Leave a specific scan group
        /// </summary>
        public async Task LeaveScanGroup(string scanId)
        {
            try
            {
                await Groups.RemoveFromGroupAsync(Context.ConnectionId, scanId);
                
                if (_userConnections.TryGetValue(Context.ConnectionId, out var userConnection))
                {
                    await Clients.OthersInGroup(scanId).SendAsync("UserLeft", userConnection);
                }

                // Update session
                if (_activeSessions.TryGetValue(scanId, out var session))
                {
                    session.ConnectedUsers = Math.Max(0, session.ConnectedUsers - 1);
                    session.LastActivity = DateTime.UtcNow;
                }

                _logger.LogInformation("User left scan group {ScanId}", scanId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error leaving scan group {ScanId}", scanId);
            }
        }

        /// <summary>
        /// Get active scan sessions
        /// </summary>
        public async Task GetActiveSessions()
        {
            var sessions = _activeSessions.Values.ToList();
            await Clients.Caller.SendAsync("ActiveSessions", sessions);
        }

        public override async Task OnConnectedAsync()
        {
            var httpContext = Context.GetHttpContext();
            var scanId = httpContext?.Request.Query["scanId"].ToString();
            var userName = httpContext?.Request.Query["userName"].ToString();
            
            if (!string.IsNullOrEmpty(scanId))
            {
                await JoinScanGroup(scanId, userName);
            }

            // Send welcome message with system status
            await Clients.Caller.SendAsync("Welcome", new
            {
                ConnectionId = Context.ConnectionId,
                ConnectedAt = DateTime.UtcNow,
                ActiveSessions = _activeSessions.Count,
                TotalConnections = _userConnections.Count
            });

            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            try
            {
                if (_userConnections.TryRemove(Context.ConnectionId, out var userConnection))
                {
                    if (!string.IsNullOrEmpty(userConnection.ScanId))
                    {
                        await LeaveScanGroup(userConnection.ScanId);
                    }

                    _logger.LogInformation("User {UserName} disconnected from scan {ScanId}", 
                        userConnection.UserName, userConnection.ScanId);
                }

                if (exception != null)
                {
                    _logger.LogWarning(exception, "Client disconnected with error");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during disconnect cleanup");
            }

            await base.OnDisconnectedAsync(exception);
        }
    }
}
