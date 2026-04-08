using System.Net;

namespace Discovery.Core.Models;

/// <summary>
/// Represents a network range with start IP, end IP, and total host count.
/// </summary>
/// <param name="StartIp">The starting IP address of the range.</param>
/// <param name="EndIp">The ending IP address of the range.</param>
/// <param name="TotalHosts">The total number of hosts in the range.</param>
public readonly record struct NetworkRange(IPAddress StartIp, IPAddress EndIp, int TotalHosts);