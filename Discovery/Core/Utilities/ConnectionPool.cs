using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using Discovery.Core.Models;

namespace Discovery.Core.Utilities;

/// <summary>
/// Connection pool for reusing TCP connections to improve performance.
/// </summary>
public static class ConnectionPool
{
    private static readonly ConcurrentDictionary<string, Queue<TcpClient>> _pool = new();
    private static readonly object _lock = new();

    /// <summary>
    /// Rents a connection from the pool for the specified target.
    /// </summary>
    /// <param name="target">The target IP address.</param>
    /// <returns>A reusable TCP client connection, or null if none available.</returns>
    public static TcpClient? RentConnection(IPAddress target)
    {
        var key = target.ToString();
        if (_pool.TryGetValue(key, out var queue))
        {
            lock (_lock)
            {
                if (queue.Count > 0)
                {
                    var client = queue.Dequeue();
                    if (client.Connected)
                        return client;
                    else
                        client.Dispose();
                }
            }
        }
        return null;
    }

    /// <summary>
    /// Returns a connection to the pool for reuse.
    /// </summary>
    /// <param name="target">The target IP address.</param>
    /// <param name="client">The TCP client to return to the pool.</param>
    public static void ReturnConnection(IPAddress target, TcpClient client)
    {
        if (!client.Connected)
        {
            client.Dispose();
            return;
        }

        var key = target.ToString();
        var queue = _pool.GetOrAdd(key, _ => new Queue<TcpClient>());
        
        lock (_lock)
        {
            if (queue.Count < 5) // Limit pool size
            {
                queue.Enqueue(client);
            }
            else
            {
                client.Dispose();
            }
        }
    }

    /// <summary>
    /// Clears all connections from the pool and disposes them.
    /// </summary>
    public static void ClearPool()
    {
        lock (_lock)
        {
            foreach (var queue in _pool.Values)
            {
                while (queue.Count > 0)
                {
                    queue.Dequeue().Dispose();
                }
            }
            _pool.Clear();
        }
    }
}