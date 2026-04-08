using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;

namespace Discovery.Core.Utilities
{
    /// <summary>
    /// Performance-oriented helper classes for network operations
    /// </summary>
    internal static class NetworkOptimizations
    {
        private static readonly ArrayPool<byte> BytePool = ArrayPool<byte>.Shared;
        private static readonly SemaphoreSlim DefaultSemaphore = new(200, 200);
        
        /// <summary>
        /// Gets an optimal semaphore based on the total number of targets.
        /// </summary>
        /// <param name="totalTargets">The total number of targets to process.</param>
        /// <returns>A semaphore with optimal concurrency limits.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static SemaphoreSlim GetOptimalSemaphore(int totalTargets) =>
            totalTargets switch
            {
                <= 50 => new SemaphoreSlim(50, 50),
                <= 500 => new SemaphoreSlim(100, 100),
                <= 2000 => new SemaphoreSlim(150, 150),
                _ => DefaultSemaphore
            };

        /// <summary>
        /// Rents a buffer from the shared byte array pool.
        /// </summary>
        /// <param name="minimumLength">The minimum length of the buffer to rent.</param>
        /// <returns>A rented byte array buffer.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] RentBuffer(int minimumLength = 4) => BytePool.Rent(minimumLength);
        
        /// <summary>
        /// Returns a buffer to the shared byte array pool.
        /// </summary>
        /// <param name="buffer">The buffer to return to the pool.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ReturnBuffer(byte[] buffer) => BytePool.Return(buffer);

        /// <summary>
        /// Adaptive timeout calculation based on network conditions
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int CalculateAdaptiveTimeout(TimeSpan averageResponseTime, int baseTimeout = 2000)
        {
            // Adjust timeout based on network performance
            var responseMs = averageResponseTime.TotalMilliseconds;
            return responseMs switch
            {
                < 10 => Math.Max(baseTimeout / 2, 500),     // Very fast network
                < 50 => (int)(baseTimeout * 0.75),         // Fast network
                < 200 => baseTimeout,                      // Normal network
                < 1000 => (int)(baseTimeout * 1.5),        // Slow network
                _ => Math.Min(baseTimeout * 2, 10000)      // Very slow network, cap at 10s
            };
        }
    
        /// <summary>
        /// Generates IP addresses asynchronously within the specified range.
        /// </summary>
        /// <param name="range">The network range to generate IPs for.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>An async enumerable of IP addresses in the range.</returns>
        public static async IAsyncEnumerable<IPAddress> GenerateIpRangeAsync(
            NetworkRange range,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var startBytes = range.StartIp.GetAddressBytes();
            var endBytes = range.EndIp.GetAddressBytes();
            
            if (startBytes.Length != 4 || endBytes.Length != 4)
                yield break;

            var start = BitConverter.ToUInt32(startBytes.AsSpan());
            var end = BitConverter.ToUInt32(endBytes.AsSpan());
            
            if (BitConverter.IsLittleEndian)
            {
                start = BinaryPrimitives.ReverseEndianness(start);
                end = BinaryPrimitives.ReverseEndianness(end);
            }

            var buffer = RentBuffer();
            try
            {
                for (var current = start; current <= end; current++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var networkOrderValue = BitConverter.IsLittleEndian 
                        ? BinaryPrimitives.ReverseEndianness(current)
                        : current;
                    
                    BitConverter.TryWriteBytes(buffer.AsSpan(), networkOrderValue);
                    yield return new IPAddress(buffer.AsSpan(0, 4));
                    
                    // Yield control periodically for better responsiveness
                    if ((current - start) % 100 == 0)
                        await Task.Yield();
                }
            }
            finally
            {
                ReturnBuffer(buffer);
            }
        }

        /// <summary>
        /// Smart batching for network operations.
        /// </summary>
        /// <typeparam name="T">The type of items to batch.</typeparam>
        /// <param name="items">The items to create batches from.</param>
        /// <param name="targetBatchSize">The target batch size, or null for automatic calculation.</param>
        /// <returns>An enumerable of batches.</returns>
        public static IEnumerable<IEnumerable<T>> CreateOptimalBatches<T>(IEnumerable<T> items, int? targetBatchSize = null)
        {
            var itemList = items.ToList();
            var totalItems = itemList.Count;
            
            // Calculate optimal batch size based on total items
            var batchSize = targetBatchSize ?? totalItems switch
            {
                <= 10 => totalItems,
                <= 100 => 10,
                <= 1000 => 50,
                _ => 100
            };

            for (int i = 0; i < totalItems; i += batchSize)
            {
                yield return itemList.Skip(i).Take(batchSize);
            }
        }
    }
}