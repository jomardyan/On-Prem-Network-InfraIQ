using Discovery.Core.Models;
using Discovery.Services.Scanning;
using Discovery.Web.Hubs;
using Discovery.Web.Models;
using Microsoft.AspNetCore.SignalR;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Discovery.Web.Services
{
    public class ScanService : IScanService
    {
        private readonly IHubContext<ScanHub> _hubContext;
        private readonly CidrScanner _cidrScanner;
        private readonly ConcurrentDictionary<string, CancellationTokenSource> _runningScans = new ConcurrentDictionary<string, CancellationTokenSource>();

        public ScanService(IHubContext<ScanHub> hubContext, CidrScanner cidrScanner)
        {
            _hubContext = hubContext;
            _cidrScanner = cidrScanner;
        }

        public Task<string> StartScanAsync(ScanRequest request)
        {
            var scanId = Guid.NewGuid().ToString();
            var cts = new CancellationTokenSource();
            _runningScans[scanId] = cts;

            _ = Task.Run(async () =>
            {
                try
                {
                    var ports = new Dictionary<int, string>();
                    if (request.Ports != null)
                    {
                        foreach (var port in request.Ports)
                        {
                            ports[port] = "";
                        }
                    }

                    var results = await _cidrScanner.ScanCidrNotation(request.Target, ports, cts);
                    await _hubContext.Clients.Group(scanId).SendAsync("ReceiveScanUpdate", new { status = "Completed", results });
                }
                catch (Exception ex)
                {
                    await _hubContext.Clients.Group(scanId).SendAsync("ReceiveScanUpdate", new { status = "Error", message = ex.Message });
                }
                finally
                {
                    _runningScans.TryRemove(scanId, out _);
                }
            }, cts.Token);

            return Task.FromResult(scanId);
        }

        public Task StopScanAsync(string scanId)
        {
            if (_runningScans.TryGetValue(scanId, out var cts))
            {
                cts.Cancel();
                _runningScans.TryRemove(scanId, out _);
            }
            return Task.CompletedTask;
        }

        public object GetScanStatus(string scanId)
        {
            if (_runningScans.ContainsKey(scanId))
            {
                return new { status = "Running" };
            }
            return new { status = "NotFound" };
        }
    }
}
