using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Discovery.Core.Utilities
{
    /// <summary>
    /// Performance monitoring for network operations
    /// </summary>
    public static class PerformanceMonitor
    {
        private static readonly ConcurrentDictionary<string, List<TimeSpan>> _metrics = new();

        /// <summary>
        /// Records the duration of a network operation for performance analysis.
        /// </summary>
        /// <param name="operationType">The type of operation being measured.</param>
        /// <param name="duration">The duration of the operation.</param>
        public static void RecordOperation(string operationType, TimeSpan duration)
        {
            var metrics = _metrics.GetOrAdd(operationType, _ => new List<TimeSpan>());
            lock (metrics)
            {
                metrics.Add(duration);
                // Keep only recent measurements
                if (metrics.Count > 100)
                {
                    metrics.RemoveAt(0);
                }
            }
        }

        /// <summary>
        /// Gets the average operation time for the specified operation type.
        /// </summary>
        /// <param name="operationType">The type of operation to get average time for.</param>
        /// <returns>The average time span for the operation type.</returns>
        public static TimeSpan GetAverageTime(string operationType)
        {
            if (_metrics.TryGetValue(operationType, out var metrics))
            {
                lock (metrics)
                {
                    return metrics.Count > 0 
                        ? TimeSpan.FromTicks((long)metrics.Average(t => t.Ticks))
                        : TimeSpan.Zero;
                }
            }
            return TimeSpan.Zero;
        }

        /// <summary>
        /// Resets all performance metrics.
        /// </summary>
        public static void Reset() => _metrics.Clear();
    }
}