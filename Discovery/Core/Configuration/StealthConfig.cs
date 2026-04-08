using System;

namespace Discovery.Core.Configuration
{
    /// <summary>
    /// Configuration class for stealth scanning features to avoid detection
    /// </summary>
    public class StealthConfig
    {
        /// <summary>
        /// Minimum delay between scan operations in milliseconds
        /// </summary>
        public int MinScanDelay { get; set; } = 100;

        /// <summary>
        /// Maximum delay between scan operations in milliseconds
        /// </summary>
        public int MaxScanDelay { get; set; } = 500;

        /// <summary>
        /// Enable random source port selection
        /// </summary>
        public bool RandomizeSourcePorts { get; set; } = true;

        /// <summary>
        /// Enable packet fragmentation for TCP scans
        /// </summary>
        public bool UsePacketFragmentation { get; set; } = false;

        /// <summary>
        /// Enable user agent rotation for HTTP requests
        /// </summary>
        public bool RotateUserAgents { get; set; } = true;

        /// <summary>
        /// Maximum concurrent connections for stealth mode
        /// </summary>
        public int MaxConcurrentConnections { get; set; } = 10;

        /// <summary>
        /// Enable scan pattern randomization
        /// </summary>
        public bool RandomizeScanPattern { get; set; } = true;

        /// <summary>
        /// Connection timeout for stealth scans in milliseconds
        /// </summary>
        public int ConnectionTimeout { get; set; } = 3000;

        /// <summary>
        /// Gets a random delay within the configured range
        /// </summary>
        public int GetRandomDelay()
        {
            var random = new Random();
            return random.Next(MinScanDelay, MaxScanDelay + 1);
        }

        /// <summary>
        /// Gets a random source port for stealth scanning
        /// </summary>
        public int GetRandomSourcePort()
        {
            if (!RandomizeSourcePorts)
                return 0; // Let system choose

            var random = new Random();
            // Use high ports to avoid privileged port issues
            return random.Next(32768, 65535);
        }

        /// <summary>
        /// Gets a random user agent string for HTTP requests
        /// </summary>
        public string GetRandomUserAgent()
        {
            if (!RotateUserAgents)
                return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

            var userAgents = new[]
            {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
            };

            var random = new Random();
            return userAgents[random.Next(userAgents.Length)];
        }

        /// <summary>
        /// Creates a default stealth configuration for normal scanning
        /// </summary>
        public static StealthConfig Default => new()
        {
            MinScanDelay = 50,
            MaxScanDelay = 200,
            RandomizeSourcePorts = false,
            UsePacketFragmentation = false,
            RotateUserAgents = false,
            MaxConcurrentConnections = 100,
            RandomizeScanPattern = false,
            ConnectionTimeout = 2000
        };

        /// <summary>
        /// Creates a high stealth configuration for avoiding detection
        /// </summary>
        public static StealthConfig HighStealth => new()
        {
            MinScanDelay = 500,
            MaxScanDelay = 2000,
            RandomizeSourcePorts = true,
            UsePacketFragmentation = true,
            RotateUserAgents = true,
            MaxConcurrentConnections = 5,
            RandomizeScanPattern = true,
            ConnectionTimeout = 5000
        };

        /// <summary>
        /// Creates a balanced stealth configuration
        /// </summary>
        public static StealthConfig Balanced => new()
        {
            MinScanDelay = 200,
            MaxScanDelay = 800,
            RandomizeSourcePorts = true,
            UsePacketFragmentation = false,
            RotateUserAgents = true,
            MaxConcurrentConnections = 25,
            RandomizeScanPattern = true,
            ConnectionTimeout = 3000
        };
    }
}