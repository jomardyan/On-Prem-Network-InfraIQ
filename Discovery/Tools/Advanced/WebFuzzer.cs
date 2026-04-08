using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Spectre.Console;

namespace Discovery.Tools.Advanced
{
    /// <summary>
    /// Web directory and file fuzzing tools (Gobuster/Dirb-like functionality)
    /// Implements comprehensive web application enumeration and API discovery
    /// </summary>
    public class WebFuzzer : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly SemaphoreSlim _semaphore;
        private static readonly string[] CommonExtensions = { "", ".html", ".php", ".asp", ".aspx", ".jsp", ".txt", ".xml", ".json", ".bak", ".old" };

        /// <summary>
        /// Initializes a new instance of the WebFuzzer class
        /// </summary>
        public WebFuzzer(int maxConcurrency = 50)
        {
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false, // Don't follow redirects automatically
                ServerCertificateCustomValidationCallback = (sender, certificate, chain, errors) => true
            };

            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(10)
            };

            _httpClient.DefaultRequestHeaders.Add("User-Agent", 
                "Mozilla/5.0 (compatible; WebFuzzer/1.0; +https://security-scanner.local)");

            _semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
        }

        /// <summary>
        /// Performs directory and file fuzzing on a web target
        /// </summary>
        /// <param name="baseUrl">Base URL to fuzz</param>
        /// <param name="wordlist">Wordlist for fuzzing</param>
        /// <param name="extensions">File extensions to test</param>
        /// <returns>Collection of discovered web resources</returns>
        public async Task<WebFuzzingResult> FuzzDirectoriesAsync(
            string baseUrl,
            IEnumerable<string> wordlist,
            IEnumerable<string>? extensions = null,
            CancellationToken cancellationToken = default)
        {
            var result = new WebFuzzingResult { BaseUrl = baseUrl };
            var words = wordlist.ToArray();
            var exts = extensions?.ToArray() ?? CommonExtensions;

            AnsiConsole.MarkupLine($"[bold cyan]🔍 Web Directory Fuzzing: {baseUrl}[/]");
            AnsiConsole.MarkupLine($"[yellow]Wordlist entries: {words.Length}[/]");
            AnsiConsole.MarkupLine($"[yellow]Extensions: {string.Join(", ", exts)}[/]");
            AnsiConsole.WriteLine();

            // Test base URL first
            var baseResponse = await TestUrl(baseUrl, cancellationToken);
            if (baseResponse != null)
            {
                result.DiscoveredResources.Add(baseResponse);
                AnsiConsole.MarkupLine($"[green]✅ Base URL accessible: {baseUrl} [{baseResponse.StatusCode}][/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[red]❌ Base URL not accessible: {baseUrl}[/]");
                return result;
            }

            var urlsToTest = GenerateTestUrls(baseUrl, words, exts);
            var discovered = new ConcurrentBag<WebResource>();

            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]🔍 Fuzzing directories and files[/]", 
                        maxValue: urlsToTest.Count);

                    var fuzzTasks = urlsToTest.Select(async url =>
                    {
                        await _semaphore.WaitAsync(cancellationToken);
                        try
                        {
                            var resource = await TestUrl(url, cancellationToken);
                            if (resource != null && IsInteresting(resource))
                            {
                                discovered.Add(resource);
                                
                                var statusColor = GetStatusColor(resource.StatusCode);
                                AnsiConsole.MarkupLine($"[{statusColor}]✅ {resource.Url} [{resource.StatusCode}] ({resource.Size} bytes)[/]");
                            }
                        }
                        finally
                        {
                            _semaphore.Release();
                            task.Increment(1);
                        }
                    });

                    await Task.WhenAll(fuzzTasks);
                });

            result.DiscoveredResources.AddRange(discovered.OrderBy(r => r.Url));
            return result;
        }

        /// <summary>
        /// Performs API endpoint discovery and testing
        /// </summary>
        /// <param name="baseUrl">Base URL for API discovery</param>
        /// <param name="apiPaths">API path wordlist</param>
        /// <returns>Collection of discovered API endpoints</returns>
        public async Task<ApiDiscoveryResult> DiscoverApiEndpointsAsync(
            string baseUrl,
            IEnumerable<string>? apiPaths = null,
            CancellationToken cancellationToken = default)
        {
            var result = new ApiDiscoveryResult { BaseUrl = baseUrl };
            var paths = apiPaths?.ToArray() ?? GetDefaultApiPaths();

            AnsiConsole.MarkupLine($"[bold cyan]🔍 API Endpoint Discovery: {baseUrl}[/]");
            AnsiConsole.MarkupLine($"[yellow]Testing {paths.Length} potential API endpoints[/]");
            AnsiConsole.WriteLine();

            var httpMethods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD" };
            var endpoints = new ConcurrentBag<ApiEndpoint>();

            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]🔍 Discovering API endpoints[/]", 
                        maxValue: paths.Length * httpMethods.Length);

                    var discoveryTasks = paths.SelectMany(path => 
                        httpMethods.Select(async method =>
                        {
                            await _semaphore.WaitAsync(cancellationToken);
                            try
                            {
                                var endpoint = await TestApiEndpoint(baseUrl, path, method, cancellationToken);
                                if (endpoint != null)
                                {
                                    endpoints.Add(endpoint);
                                    
                                    var statusColor = GetStatusColor(endpoint.StatusCode);
                                    AnsiConsole.MarkupLine($"[{statusColor}]✅ {endpoint.Method} {endpoint.Path} [{endpoint.StatusCode}][/]");
                                }
                            }
                            finally
                            {
                                _semaphore.Release();
                                task.Increment(1);
                            }
                        }));

                    await Task.WhenAll(discoveryTasks);
                });

            result.ApiEndpoints.AddRange(endpoints.OrderBy(e => e.Path).ThenBy(e => e.Method));
            
            // Analyze API patterns
            AnalyzeApiPatterns(result);

            return result;
        }

        /// <summary>
        /// Performs parameter fuzzing on web applications
        /// </summary>
        /// <param name="baseUrl">Base URL to test</param>
        /// <param name="parameterNames">Parameter names to test</param>
        /// <returns>Collection of discovered parameters</returns>
        public async Task<ParameterFuzzingResult> FuzzParametersAsync(
            string baseUrl,
            IEnumerable<string>? parameterNames = null,
            CancellationToken cancellationToken = default)
        {
            var result = new ParameterFuzzingResult { BaseUrl = baseUrl };
            var parameters = parameterNames?.ToArray() ?? GetCommonParameters();

            AnsiConsole.MarkupLine($"[bold cyan]🔍 Parameter Fuzzing: {baseUrl}[/]");
            AnsiConsole.MarkupLine($"[yellow]Testing {parameters.Length} parameters[/]");
            AnsiConsole.WriteLine();

            var discoveredParams = new ConcurrentBag<FuzzedParameter>();

            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]🔍 Fuzzing parameters[/]", 
                        maxValue: parameters.Length);

                    var paramTasks = parameters.Select(async param =>
                    {
                        await _semaphore.WaitAsync(cancellationToken);
                        try
                        {
                            var fuzzedParam = await TestParameter(baseUrl, param, cancellationToken);
                            if (fuzzedParam != null)
                            {
                                discoveredParams.Add(fuzzedParam);
                                AnsiConsole.MarkupLine($"[green]✅ Parameter found: {fuzzedParam.Name} (Type: {fuzzedParam.Type})[/]");
                            }
                        }
                        finally
                        {
                            _semaphore.Release();
                            task.Increment(1);
                        }
                    });

                    await Task.WhenAll(paramTasks);
                });

            result.DiscoveredParameters.AddRange(discoveredParams.OrderBy(p => p.Name));
            return result;
        }

        /// <summary>
        /// Tests a single URL and returns resource information
        /// </summary>
        private async Task<WebResource?> TestUrl(string url, CancellationToken cancellationToken)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                using var response = await _httpClient.SendAsync(request, cancellationToken);

                var content = string.Empty;
                var size = 0L;

                if (response.Content != null)
                {
                    var contentBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                    size = contentBytes.Length;
                    content = Encoding.UTF8.GetString(contentBytes.Take(1000).ToArray()); // First 1KB for analysis
                }

                return new WebResource
                {
                    Url = url,
                    StatusCode = (int)response.StatusCode,
                    Size = size,
                    ContentType = response.Content?.Headers?.ContentType?.ToString() ?? string.Empty,
                    Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value)),
                    Content = content,
                    ResponseTime = TimeSpan.FromMilliseconds(100), // Simplified for demo
                    DiscoveredAt = DateTime.UtcNow
                };
            }
            catch (TaskCanceledException)
            {
                throw; // Re-throw cancellation
            }
            catch (Exception)
            {
                return null; // URL not accessible
            }
        }

        /// <summary>
        /// Tests an API endpoint with a specific HTTP method
        /// </summary>
        private async Task<ApiEndpoint?> TestApiEndpoint(
            string baseUrl,
            string path,
            string method,
            CancellationToken cancellationToken)
        {
            try
            {
                var url = $"{baseUrl.TrimEnd('/')}/{path.TrimStart('/')}";
                using var request = new HttpRequestMessage(new HttpMethod(method), url);
                
                // Add common API headers
                request.Headers.Add("Accept", "application/json");
                if (method == "POST" || method == "PUT" || method == "PATCH")
                {
                    request.Content = new StringContent("{}", Encoding.UTF8, "application/json");
                }

                using var response = await _httpClient.SendAsync(request, cancellationToken);

                // Only consider successful responses or meaningful errors
                if ((int)response.StatusCode < 500 && response.StatusCode != HttpStatusCode.NotFound)
                {
                    var responseBody = string.Empty;
                    if (response.Content != null)
                    {
                        responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
                    }

                    return new ApiEndpoint
                    {
                        Path = path,
                        Method = method,
                        StatusCode = (int)response.StatusCode,
                        ContentType = response.Content?.Headers?.ContentType?.ToString() ?? string.Empty,
                        RequiresAuth = response.StatusCode == HttpStatusCode.Unauthorized,
                        ResponseBody = responseBody.Length > 500 ? responseBody[..500] + "..." : responseBody,
                        Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value)),
                        DiscoveredAt = DateTime.UtcNow
                    };
                }
            }
            catch (TaskCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                // Endpoint not accessible with this method
            }

            return null;
        }

        /// <summary>
        /// Tests a parameter for existence and behavior
        /// </summary>
        private async Task<FuzzedParameter?> TestParameter(
            string baseUrl,
            string paramName,
            CancellationToken cancellationToken)
        {
            try
            {
                // Test different parameter values to determine type and behavior
                var testValues = new[]
                {
                    ("test", "string"),
                    ("123", "integer"),
                    ("true", "boolean"),
                    ("test@example.com", "email"),
                    ("../", "path_traversal"),
                    ("'", "sql_injection"),
                    ("<script>", "xss")
                };

                var responses = new List<(string value, string type, HttpResponseMessage response)>();

                foreach (var (value, type) in testValues)
                {
                    var testUrl = $"{baseUrl}?{paramName}={WebUtility.UrlEncode(value)}";
                    
                    try
                    {
                        using var request = new HttpRequestMessage(HttpMethod.Get, testUrl);
                        using var response = await _httpClient.SendAsync(request, cancellationToken);
                        responses.Add((value, type, response));
                    }
                    catch (Exception)
                    {
                        // Continue with other test values
                    }

                    await Task.Delay(100, cancellationToken); // Rate limiting
                }

                // Analyze responses to determine if parameter exists and its characteristics
                if (responses.Any())
                {
                    var differentResponses = responses.GroupBy(r => r.response.StatusCode).Count();
                    if (differentResponses > 1) // Parameter affects response
                    {
                        return new FuzzedParameter
                        {
                            Name = paramName,
                            Type = DetermineParameterType(responses),
                            IsVulnerable = CheckForVulnerabilities(responses),
                            TestResponses = responses.Select(r => $"{r.type}: {r.response.StatusCode}").ToList(),
                            DiscoveredAt = DateTime.UtcNow
                        };
                    }
                }
            }
            catch (TaskCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                // Parameter testing failed
            }

            return null;
        }

        /// <summary>
        /// Generates test URLs from wordlist and extensions
        /// </summary>
        private static List<string> GenerateTestUrls(string baseUrl, string[] wordlist, string[] extensions)
        {
            var urls = new List<string>();
            var cleanBaseUrl = baseUrl.TrimEnd('/');

            foreach (var word in wordlist)
            {
                foreach (var ext in extensions)
                {
                    urls.Add($"{cleanBaseUrl}/{word}{ext}");
                }
            }

            return urls;
        }

        /// <summary>
        /// Determines if a web resource is interesting for security analysis
        /// </summary>
        private static bool IsInteresting(WebResource resource)
        {
            // Skip common not found and error responses
            if (resource.StatusCode == 404 || resource.StatusCode >= 500)
                return false;

            // Include redirects, successful responses, and auth required
            return resource.StatusCode == 200 || 
                   resource.StatusCode == 301 || 
                   resource.StatusCode == 302 || 
                   resource.StatusCode == 401 || 
                   resource.StatusCode == 403;
        }

        /// <summary>
        /// Gets color for status code display
        /// </summary>
        private static string GetStatusColor(int statusCode)
        {
            return statusCode switch
            {
                200 => "green",
                301 or 302 => "yellow",
                401 or 403 => "orange1",
                >= 400 and < 500 => "red",
                >= 500 => "purple",
                _ => "white"
            };
        }

        /// <summary>
        /// Gets default API paths for discovery
        /// </summary>
        private static string[] GetDefaultApiPaths()
        {
            return new[]
            {
                "api", "api/v1", "api/v2", "rest", "graphql",
                "api/users", "api/auth", "api/login", "api/admin",
                "api/config", "api/status", "api/health", "api/version",
                "api/docs", "api/swagger", "swagger", "swagger-ui",
                "docs", "documentation", "openapi.json", "swagger.json",
                "admin", "admin/api", "manage", "management",
                "dashboard", "panel", "control", "console"
            };
        }

        /// <summary>
        /// Gets common parameter names for fuzzing
        /// </summary>
        private static string[] GetCommonParameters()
        {
            return new[]
            {
                "id", "user", "username", "email", "password", "token",
                "search", "query", "q", "filter", "sort", "order",
                "page", "limit", "offset", "count", "size",
                "file", "path", "url", "redirect", "callback",
                "debug", "test", "admin", "key", "secret",
                "lang", "language", "locale", "format", "type"
            };
        }

        /// <summary>
        /// Analyzes API patterns from discovered endpoints
        /// </summary>
        private static void AnalyzeApiPatterns(ApiDiscoveryResult result)
        {
            var patterns = new List<string>();

            // Check for versioning patterns
            if (result.ApiEndpoints.Any(e => e.Path.Contains("/v1/") || e.Path.Contains("/v2/")))
            {
                patterns.Add("API versioning detected");
            }

            // Check for REST patterns
            var restfulEndpoints = result.ApiEndpoints.Count(e => 
                e.Method == "GET" || e.Method == "POST" || e.Method == "PUT" || e.Method == "DELETE");
            
            if (restfulEndpoints > 0)
            {
                patterns.Add($"RESTful API patterns detected ({restfulEndpoints} endpoints)");
            }

            // Check for authentication patterns
            var authEndpoints = result.ApiEndpoints.Count(e => e.RequiresAuth);
            if (authEndpoints > 0)
            {
                patterns.Add($"Authentication required for {authEndpoints} endpoints");
            }

            result.AnalysisResults = patterns;
        }

        /// <summary>
        /// Determines parameter type from test responses
        /// </summary>
        private static string DetermineParameterType(List<(string value, string type, HttpResponseMessage response)> responses)
        {
            // Simple heuristic - in production would be more sophisticated
            var successfulTypes = responses
                .Where(r => r.response.IsSuccessStatusCode)
                .Select(r => r.type)
                .ToList();

            return successfulTypes.FirstOrDefault() ?? "unknown";
        }

        /// <summary>
        /// Checks for potential vulnerabilities in parameter responses
        /// </summary>
        private static bool CheckForVulnerabilities(List<(string value, string type, HttpResponseMessage response)> responses)
        {
            // Check for potential injection vulnerabilities
            var dangerousResponses = responses.Where(r => 
                r.type == "sql_injection" || r.type == "xss" || r.type == "path_traversal");

            foreach (var (value, type, response) in dangerousResponses)
            {
                if (response.IsSuccessStatusCode || response.StatusCode != HttpStatusCode.BadRequest)
                {
                    return true; // Potential vulnerability - dangerous input accepted
                }
            }

            return false;
        }

        /// <summary>
        /// Gets built-in directory wordlist
        /// </summary>
        public static string[] GetBuiltInWordlist()
        {
            return new[]
            {
                "admin", "administrator", "api", "app", "assets", "backup", "bin",
                "blog", "config", "css", "data", "db", "debug", "docs", "download",
                "error", "files", "images", "img", "includes", "js", "lib", "log",
                "logs", "old", "pages", "private", "public", "scripts", "src",
                "temp", "test", "tmp", "upload", "uploads", "user", "users",
                "var", "web", "wp-admin", "wp-content", "wp-includes",
                "index", "home", "about", "contact", "login", "logout", "register",
                "search", "sitemap", "robots.txt", ".htaccess", "web.config",
                "phpinfo", "info", "status", "health", "version", "readme"
            };
        }

        /// <summary>
        /// Releases resources
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
            _semaphore?.Dispose();
        }
    }

    #region Data Models

    /// <summary>
    /// Web fuzzing result
    /// </summary>
    public class WebFuzzingResult
    {
        public string BaseUrl { get; set; } = string.Empty;
        public List<WebResource> DiscoveredResources { get; set; } = new();
        public DateTime ScanTime { get; set; } = DateTime.UtcNow;
        public TimeSpan ScanDuration { get; set; }
    }

    /// <summary>
    /// Discovered web resource
    /// </summary>
    public class WebResource
    {
        public string Url { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public long Size { get; set; }
        public string ContentType { get; set; } = string.Empty;
        public Dictionary<string, string> Headers { get; set; } = new();
        public string Content { get; set; } = string.Empty;
        public TimeSpan ResponseTime { get; set; }
        public DateTime DiscoveredAt { get; set; }
    }

    /// <summary>
    /// API discovery result
    /// </summary>
    public class ApiDiscoveryResult
    {
        public string BaseUrl { get; set; } = string.Empty;
        public List<ApiEndpoint> ApiEndpoints { get; set; } = new();
        public List<string> AnalysisResults { get; set; } = new();
        public DateTime ScanTime { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Discovered API endpoint
    /// </summary>
    public class ApiEndpoint
    {
        public string Path { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public string ContentType { get; set; } = string.Empty;
        public bool RequiresAuth { get; set; }
        public string ResponseBody { get; set; } = string.Empty;
        public Dictionary<string, string> Headers { get; set; } = new();
        public DateTime DiscoveredAt { get; set; }
    }

    /// <summary>
    /// Parameter fuzzing result
    /// </summary>
    public class ParameterFuzzingResult
    {
        public string BaseUrl { get; set; } = string.Empty;
        public List<FuzzedParameter> DiscoveredParameters { get; set; } = new();
        public DateTime ScanTime { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Discovered parameter
    /// </summary>
    public class FuzzedParameter
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public bool IsVulnerable { get; set; }
        public List<string> TestResponses { get; set; } = new();
        public DateTime DiscoveredAt { get; set; }
    }

    #endregion
}