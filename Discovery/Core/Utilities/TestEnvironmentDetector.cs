using System;
using System.Diagnostics;
using System.Reflection;

namespace Discovery.Core.Utilities
{
    /// <summary>
    /// Utility class to detect if the application is running in a test environment
    /// </summary>
    public static class TestEnvironmentDetector
    {
        private static bool? _isTestEnvironment;

        /// <summary>
        /// Gets a value indicating whether the application is running in a test environment
        /// </summary>
        public static bool IsTestEnvironment
        {
            get
            {
                if (_isTestEnvironment.HasValue)
                    return _isTestEnvironment.Value;

                _isTestEnvironment = DetectTestEnvironment();
                return _isTestEnvironment.Value;
            }
        }

        /// <summary>
        /// Detects if the application is running in a test environment
        /// </summary>
        private static bool DetectTestEnvironment()
        {
            // Check if we're running under a test runner
            var processName = Process.GetCurrentProcess().ProcessName.ToLowerInvariant();
            if (processName.Contains("testhost") || 
                processName.Contains("dotnet") || 
                processName.Contains("vstest") ||
                processName.Contains("nunit") ||
                processName.Contains("xunit"))
            {
                return true;
            }

            // Check for test framework assemblies in the call stack
            var assemblies = AppDomain.CurrentDomain.GetAssemblies();
            foreach (var assembly in assemblies)
            {
                var assemblyName = assembly.GetName().Name?.ToLowerInvariant();
                if (assemblyName != null && (
                    assemblyName.Contains("xunit") ||
                    assemblyName.Contains("nunit") ||
                    assemblyName.Contains("mstest") ||
                    assemblyName.Contains("testhost") ||
                    assemblyName.Contains("microsoft.testplatform")))
                {
                    return true;
                }
            }

            // Check environment variables that are typically set by test runners
            var environmentVariables = new[]
            {
                "DOTNET_RUNNING_IN_CONTAINER",
                "VSTEST_HOST_DEBUG",
                "TESTRUNNER",
                "CI", // Common in CI environments
                "BUILD_BUILDID" // Azure DevOps
            };

            foreach (var envVar in environmentVariables)
            {
                if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(envVar)))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Forces the test environment detection to be re-evaluated
        /// </summary>
        public static void Reset()
        {
            _isTestEnvironment = null;
        }
    }
}