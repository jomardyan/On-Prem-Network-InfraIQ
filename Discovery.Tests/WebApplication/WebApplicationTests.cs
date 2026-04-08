using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Xunit;
using Discovery.Web;
using Discovery.Web.Models;

namespace Discovery.Tests.WebApplication;

/// <summary>
/// Request model for IP scanning - local definition for testing
/// </summary>
public record ScanIpRequest(
    string IpAddress,
    int[]? Ports = null,
    int? TimeoutMs = null
);

/// <summary>
/// Request model for network scanning - local definition for testing
/// </summary>
public record ScanNetworkRequest(
    string NetworkRange,
    int[]? Ports = null,
    int? TimeoutMs = null
);

/// <summary>
/// Request model for vulnerability scanning - local definition for testing
/// </summary>
public record VulnerabilityAssessmentRequest(
    string Target,
    int[]? Ports = null,
    int? TimeoutMs = null
);

/// <summary>
/// Comprehensive tests for the web application API endpoints
/// </summary>
public class WebApplicationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public WebApplicationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task GetStatus_ShouldReturnOk()
    {
        // Act
        var response = await _client.GetAsync("/api/NetworkScan/status");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var status = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(status.TryGetProperty("status", out var statusProp));
        Assert.Equal("Online", statusProp.GetString());
    }

    [Fact]
    public async Task Dashboard_Index_ShouldReturnOk()
    {
        // Act
        var response = await _client.GetAsync("/");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("On-Prem Network InfraIQ", content);
    }

    [Fact]
    public async Task Dashboard_Scanner_ShouldReturnOk()
    {
        // Act
        var response = await _client.GetAsync("/Dashboard/Scanner");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("Network Scanner", content);
    }

    [Fact]
    public async Task ScanIpAddress_ValidRequest_ShouldReturnResults()
    {
        // Arrange
        var request = new ScanIpRequest(
            IpAddress: "127.0.0.1",
            Ports: [80, 443],
            TimeoutMs: 1000
        );

        var json = JsonSerializer.Serialize(request);
        var stringContent = new StringContent(json, Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/NetworkScan/scan-ip", stringContent);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var results = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(results.ValueKind == JsonValueKind.Array || results.ValueKind == JsonValueKind.Object);
    }

    [Fact]
    public async Task ScanIpAddress_InvalidIp_ShouldReturnBadRequest()
    {
        // Arrange
        var request = new ScanIpRequest(
            IpAddress: "invalid-ip",
            Ports: [80]
        );

        var json = JsonSerializer.Serialize(request);
        var stringContent = new StringContent(json, Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/NetworkScan/scan-ip", stringContent);

        // Assert
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task AdvancedScan_ValidRequest_ShouldReturnResults()
    {
        // Arrange
        var request = new AdvancedScanRequest
        {
            Target = "127.0.0.1",
            Ports = [80, 443],
            Timeout = 1000,
            EnableVulnerabilityScanning = false, // Disable to avoid complexity in test
            IncludeBannerGrabbing = true,
            IncludeSslAnalysis = false
        };

        var json = JsonSerializer.Serialize(request);
        var stringContent = new StringContent(json, Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/NetworkScan/advanced-scan", stringContent);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("sessionId", out _));
        Assert.True(result.TryGetProperty("scanResults", out _));
    }

    [Fact]
    public async Task ScanNetwork_ValidCidr_ShouldReturnResults()
    {
        // Arrange - Use a small range for testing
        var request = new ScanNetworkRequest(
            NetworkRange: "127.0.0.1/32", // Single host range
            Ports: [80],
            TimeoutMs: 500
        );

        var json = JsonSerializer.Serialize(request);
        var stringContent = new StringContent(json, Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/NetworkScan/scan-network", stringContent);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("sessionId", out _));
    }

    [Fact]
    public async Task DatabaseStatus_ShouldReturnOk()
    {
        // Act
        var response = await _client.GetAsync("/api/Database/status");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var status = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(status.TryGetProperty("status", out var statusProp));
        Assert.Equal("Connected", statusProp.GetString());
    }

    [Fact]
    public async Task GetScanSessions_ShouldReturnOk()
    {
        // Act
        var response = await _client.GetAsync("/api/Database/scan-sessions");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("sessions", out _));
        Assert.True(result.TryGetProperty("totalCount", out _));
    }

    [Fact]
    public async Task VulnerabilityAssessment_ValidRequest_ShouldReturnResults()
    {
        // Arrange
        var request = new VulnerabilityAssessmentRequest(
            Target: "127.0.0.1",
            Ports: [80], // Reduced to just one port
            TimeoutMs: 500 // Reduced timeout
        );

        var json = JsonSerializer.Serialize(request);
        var stringContent = new StringContent(json, Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/Vulnerability/scan-host", stringContent);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("sessionId", out _));
        Assert.True(result.TryGetProperty("vulnerabilities", out _));
    }

    [Fact]
    public async Task CloudAwsDiscover_ShouldReturnResults()
    {
        // Act
        var response = await _client.PostAsync("/api/Cloud/aws/discover?region=us-east-1", null);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        // Should return mock data structure
        Assert.True(result.TryGetProperty("resources", out var resources));
        Assert.True(resources.TryGetProperty("eC2Instances", out _));
    }

    [Fact]
    public async Task CloudAzureDiscover_ShouldReturnResults()
    {
        // Act
        var response = await _client.PostAsync("/api/Cloud/azure/discover", null);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        // Should return mock data structure
        Assert.True(result.TryGetProperty("resources", out var resources));
        Assert.True(resources.TryGetProperty("virtualMachines", out _));
    }

    [Fact]
    public async Task CloudGcpDiscover_ShouldReturnResults()
    {
        // Arrange
        var stringContent = new StringContent("", Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/Cloud/gcp/discover", stringContent);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        // Should return mock data structure
        Assert.True(result.TryGetProperty("resources", out var resources));
        Assert.True(resources.TryGetProperty("computeInstances", out _));
    }

    [Fact]
    public async Task InitializeDatabase_ShouldReturnSuccess()
    {
        // Act
        var response = await _client.PostAsync("/api/Database/initialize", null);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("success", out var successProp));
        Assert.True(successProp.GetBoolean());
    }

    [Fact]
    public async Task IPv6Scan_ValidRequest_ShouldReturnResults()
    {
        // Arrange - Use localhost IPv6
        var request = new IPv6ScanRequest(
            IPv6Address: "::1",
            Ports: [80],
            TimeoutMs: 1000,
            DiscoverNeighbors: false
        );

        var json = JsonSerializer.Serialize(request);
        var stringContent = new StringContent(json, Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/NetworkScan/scan-ipv6", stringContent);

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("target", out _));
    }

    [Fact]
    public async Task ExportScanData_ValidFormat_ShouldReturnData()
    {
        // Arrange
        var sessionId = Guid.NewGuid().ToString();

        // Act
        var response = await _client.GetAsync($"/api/Database/scan-sessions/{sessionId}/export?format=json");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("sessionId", out var sessionIdProp));
        Assert.Equal(sessionId, sessionIdProp.GetString());
    }

    [Fact]
    public async Task GetScanResults_ValidSessionId_ShouldReturnResults()
    {
        // Arrange
        var sessionId = Guid.NewGuid().ToString();

        // Act
        var response = await _client.GetAsync($"/api/Database/scan-sessions/{sessionId}/results");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("sessionId", out _));
        Assert.True(result.TryGetProperty("results", out _));
    }

    [Fact]
    public async Task DeleteSession_ValidSessionId_ShouldReturnSuccess()
    {
        // Arrange
        var sessionId = Guid.NewGuid().ToString();

        // Act
        var response = await _client.DeleteAsync($"/api/Database/scan-sessions/{sessionId}");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(result.TryGetProperty("success", out var successProp));
        Assert.True(successProp.GetBoolean());
    }

    [Fact]
    public async Task SwaggerUI_ShouldBeAccessible()
    {
        // Act
        var response = await _client.GetAsync("/swagger");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("swagger", content.ToLowerInvariant());
    }

    [Fact]
    public async Task StaticFiles_ShouldBeAccessible()
    {
        // Act - Try to access a CSS file
        var response = await _client.GetAsync("/css/site.css");

        // Assert
        Assert.True(response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.NotFound);
        // Not Found is acceptable if the file doesn't exist, but should not throw errors
    }

    [Fact]
    public async Task PerformanceTest_MultipleRequests_ShouldHandleConcurrency()
    {
        // Arrange
        var tasks = new List<Task<HttpResponseMessage>>();
        
        for (int i = 0; i < 5; i++)
        {
            tasks.Add(_client.GetAsync("/api/NetworkScan/status"));
        }

        // Act
        var responses = await Task.WhenAll(tasks);

        // Assert
        foreach (var response in responses)
        {
            Assert.True(response.IsSuccessStatusCode);
        }
    }

    [Fact]
    public async Task ErrorHandling_InvalidJsonRequest_ShouldReturnBadRequest()
    {
        // Arrange
        var invalidJson = new StringContent("{ invalid json }", Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/NetworkScan/scan-ip", invalidJson);

        // Assert
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ContentType_JsonEndpoints_ShouldReturnJsonContent()
    {
        // Act
        var response = await _client.GetAsync("/api/NetworkScan/status");

        // Assert
        Assert.True(response.IsSuccessStatusCode);
        Assert.Contains("application/json", response.Content.Headers.ContentType?.MediaType ?? "");
    }
}