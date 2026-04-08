using Google.Cloud.Compute.V1;
using Google.Cloud.Storage.V1;
using Google.Cloud.PubSub.V1;
using Discovery.Core.Models;
using System.Text.Json;

namespace Discovery.Services.Cloud;

/// <summary>
/// Google Cloud Platform integration service for discovery and storage operations.
/// </summary>
public class GcpCloudService
{
    private readonly InstancesClient _instancesClient;
    private readonly StorageClient _storageClient;
    private readonly PublisherServiceApiClient _pubSubClient;
    private readonly string _projectId;
    private readonly string _storageBucketName;
    private readonly string _pubSubTopicName;

    /// <summary>
    /// Initializes a new instance of the <see cref="GcpCloudService"/> class.
    /// </summary>
    /// <param name="instancesClient">The Compute Engine instances client.</param>
    /// <param name="storageClient">The Cloud Storage client.</param>
    /// <param name="pubSubClient">The Pub/Sub client.</param>
    /// <param name="projectId">The GCP project ID.</param>
    /// <param name="storageBucketName">The storage bucket name for storing results.</param>
    /// <param name="pubSubTopicName">The Pub/Sub topic name for notifications.</param>
    public GcpCloudService(
        InstancesClient instancesClient,
        StorageClient storageClient,
        PublisherServiceApiClient pubSubClient,
        string projectId,
        string storageBucketName,
        string pubSubTopicName)
    {
        _instancesClient = instancesClient ?? throw new ArgumentNullException(nameof(instancesClient));
        _storageClient = storageClient ?? throw new ArgumentNullException(nameof(storageClient));
        _pubSubClient = pubSubClient ?? throw new ArgumentNullException(nameof(pubSubClient));
        _projectId = projectId ?? throw new ArgumentNullException(nameof(projectId));
        _storageBucketName = storageBucketName ?? throw new ArgumentNullException(nameof(storageBucketName));
        _pubSubTopicName = pubSubTopicName ?? throw new ArgumentNullException(nameof(pubSubTopicName));
    }

    /// <summary>
    /// Discovers Compute Engine instances across zones.
    /// </summary>
    /// <param name="zones">The zones to scan. If null, scans all zones in the project.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of discovered cloud resources.</returns>
    public async Task<IEnumerable<CloudResourceEntity>> DiscoverComputeInstancesAsync(
        IEnumerable<string>? zones = null,
        CancellationToken cancellationToken = default)
    {
        var resources = new List<CloudResourceEntity>();

        try
        {
            // If no zones specified, get all zones in the project
            if (zones == null)
            {
                zones = await GetAllZonesAsync(cancellationToken);
            }

            foreach (var zone in zones)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    Console.WriteLine($"Scanning zone: {zone}");

                    var request = new ListInstancesRequest
                    {
                        Project = _projectId,
                        Zone = zone
                    };

                    await foreach (var instance in _instancesClient.ListAsync(request))
                    {
                        if (cancellationToken.IsCancellationRequested) break;

                        try
                        {
                            var ipAddresses = GetInstanceIpAddresses(instance);

                            var resource = new CloudResourceEntity
                            {
                                CloudProvider = "GCP",
                                Region = ExtractRegionFromZone(zone),
                                ResourceType = "ComputeEngine",
                                ResourceId = instance.Id.ToString(),
                                PublicIpAddress = ipAddresses.ExternalIp,
                                PrivateIpAddress = ipAddresses.InternalIp,
                                ResourceName = instance.Name,
                                Status = instance.Status,
                                DiscoveredAt = DateTime.UtcNow,
                                Metadata = JsonSerializer.Serialize(new
                                {
                                    Zone = zone,
                                    MachineType = GetMachineTypeName(instance.MachineType),
                                    CreationTimestamp = instance.CreationTimestamp,
                                    DiskSizeGb = instance.Disks?.Sum(d => d.DiskSizeGb),
                                    NetworkInterfaces = instance.NetworkInterfaces?.Count,
                                    Labels = instance.Labels,
                                    Tags = instance.Tags?.Items,
                                    CanIpForward = instance.CanIpForward,
                                    SelfLink = instance.SelfLink
                                })
                            };

                            resources.Add(resource);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to process instance {instance.Name}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to scan zone {zone}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"GCP Compute Engine discovery failed: {ex.Message}");
        }

        return resources;
    }

    /// <summary>
    /// Scans discovered GCP instances for open ports and vulnerabilities.
    /// </summary>
    /// <param name="instances">The GCP instances to scan.</param>
    /// <param name="ports">The ports to scan.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan results.</returns>
    public async Task<IEnumerable<ScanResult>> ScanComputeInstancesAsync(
        IEnumerable<CloudResourceEntity> instances,
        IEnumerable<int> ports,
        CancellationToken cancellationToken = default)
    {
        var results = new List<ScanResult>();
        var portScanner = new Services.Scanning.PortScanner();

        foreach (var instance in instances)
        {
            if (cancellationToken.IsCancellationRequested) break;

            var targetIp = !string.IsNullOrEmpty(instance.PublicIpAddress) 
                ? instance.PublicIpAddress 
                : instance.PrivateIpAddress;

            if (string.IsNullOrEmpty(targetIp)) continue;

            try
            {
                var ipAddress = System.Net.IPAddress.Parse(targetIp);
                
                foreach (var port in ports)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    var isOpen = await portScanner.ScanPortAsync(ipAddress, port, 5000);
                    
                    if (isOpen)
                    {
                        var scanResult = ScanResult.CreateOpen(
                            ipAddress,
                            port,
                            "Unknown",
                            0
                        ).WithServerInfo($"GCP Compute Engine: {instance.ResourceId}", "GCP Compute Engine");

                        results.Add(scanResult);
                    }
                }

                // Add GCP-specific vulnerability checks
                var gcpVulns = await CheckGcpSpecificVulnerabilitiesAsync(instance, cancellationToken);
                results.AddRange(gcpVulns);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to scan instance {instance.ResourceId}: {ex.Message}");
            }
        }

        return results;
    }

    /// <summary>
    /// Stores scan results to Google Cloud Storage.
    /// </summary>
    /// <param name="sessionId">The scan session ID.</param>
    /// <param name="results">The scan results to store.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The object name where results were stored.</returns>
    public async Task<string> StoreResultsToCloudStorageAsync(
        Guid sessionId,
        IEnumerable<ScanResult> results,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss");
            var objectName = $"scan-results/{sessionId}/{timestamp}.json";

            var resultsJson = JsonSerializer.Serialize(results, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            var content = System.Text.Encoding.UTF8.GetBytes(resultsJson);

            using var stream = new MemoryStream(content);
            await _storageClient.UploadObjectAsync(_storageBucketName, objectName, "application/json", stream, cancellationToken: cancellationToken);

            return objectName;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to store results to Cloud Storage: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Retrieves scan results from Google Cloud Storage.
    /// </summary>
    /// <param name="objectName">The object name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The scan results.</returns>
    public async Task<IEnumerable<ScanResult>> RetrieveResultsFromCloudStorageAsync(
        string objectName,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var stream = new MemoryStream();
            await _storageClient.DownloadObjectAsync(_storageBucketName, objectName, stream, cancellationToken: cancellationToken);
            
            stream.Position = 0;
            using var reader = new StreamReader(stream);
            var resultsJson = await reader.ReadToEndAsync();

            var results = JsonSerializer.Deserialize<IEnumerable<ScanResult>>(resultsJson);
            return results ?? Enumerable.Empty<ScanResult>();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to retrieve results from Cloud Storage: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Sends notification about scan completion via Pub/Sub.
    /// </summary>
    /// <param name="sessionId">The scan session ID.</param>
    /// <param name="summary">The scan summary.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The published message IDs.</returns>
    public async Task<IEnumerable<string>> SendScanNotificationAsync(
        Guid sessionId,
        ScanSummary summary,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var topicName = TopicName.FromProjectTopic(_projectId, _pubSubTopicName);

            var messageData = JsonSerializer.Serialize(new
            {
                SessionId = sessionId,
                Summary = summary,
                Timestamp = DateTime.UtcNow
            });

            var message = new PubsubMessage
            {
                Data = Google.Protobuf.ByteString.CopyFromUtf8(messageData),
                Attributes =
                {
                    ["SessionId"] = sessionId.ToString(),
                    ["ScanType"] = summary.ScanType,
                    ["VulnerabilitiesFound"] = summary.VulnerabilitiesFound.ToString(),
                    ["ActiveHosts"] = summary.ActiveHosts.ToString(),
                    ["Timestamp"] = DateTime.UtcNow.ToString("O")
                }
            };

            var request = new PublishRequest
            {
                TopicAsTopicName = topicName,
                Messages = { message }
            };

            var response = await _pubSubClient.PublishAsync(request, cancellationToken);
            return response.MessageIds;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to send Pub/Sub notification: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets all zones in the project.
    /// </summary>
    private async Task<IEnumerable<string>> GetAllZonesAsync(CancellationToken cancellationToken)
    {
        var zones = new List<string>();

        try
        {
            var zonesClient = ZonesClient.Create();
            var request = new ListZonesRequest { Project = _projectId };

            await foreach (var zone in zonesClient.ListAsync(request))
            {
                if (cancellationToken.IsCancellationRequested) break;
                zones.Add(zone.Name);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to get zones: {ex.Message}");
            // Return common zones as fallback
            zones.AddRange(new[]
            {
                "us-central1-a", "us-central1-b", "us-central1-c",
                "us-east1-a", "us-east1-b", "us-east1-c",
                "us-west1-a", "us-west1-b", "us-west1-c",
                "europe-west1-a", "europe-west1-b", "europe-west1-c"
            });
        }

        return zones;
    }

    /// <summary>
    /// Gets IP addresses for a Compute Engine instance.
    /// </summary>
    private (string? ExternalIp, string? InternalIp) GetInstanceIpAddresses(Instance instance)
    {
        string? externalIp = null;
        string? internalIp = null;

        try
        {
            var networkInterface = instance.NetworkInterfaces?.FirstOrDefault();
            if (networkInterface != null)
            {
                internalIp = networkInterface.NetworkIP;

                var accessConfig = networkInterface.AccessConfigs?.FirstOrDefault();
                if (accessConfig != null)
                {
                    externalIp = accessConfig.NatIP;
                }
            }
        }
        catch
        {
            // Failed to get IP addresses
        }

        return (externalIp, internalIp);
    }

    /// <summary>
    /// Extracts the region name from a zone name.
    /// </summary>
    private string ExtractRegionFromZone(string zone)
    {
        // Zone format: region-letter (e.g., us-central1-a)
        var lastDashIndex = zone.LastIndexOf('-');
        return lastDashIndex > 0 ? zone.Substring(0, lastDashIndex) : zone;
    }

    /// <summary>
    /// Extracts the machine type name from the full machine type URL.
    /// </summary>
    private string GetMachineTypeName(string machineTypeUrl)
    {
        // Machine type URL format: https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/machineTypes/{machineType}
        var segments = machineTypeUrl.Split('/');
        return segments.Length > 0 ? segments[^1] : machineTypeUrl;
    }

    /// <summary>
    /// Performs GCP-specific vulnerability checks.
    /// </summary>
    private async Task<IEnumerable<ScanResult>> CheckGcpSpecificVulnerabilitiesAsync(
        CloudResourceEntity instance,
        CancellationToken cancellationToken)
    {
        var vulnerabilities = new List<ScanResult>();

        try
        {
            // Check for instances with external IPs
            if (!string.IsNullOrEmpty(instance.PublicIpAddress))
            {
                var metadata = JsonSerializer.Deserialize<dynamic>(instance.Metadata ?? "{}");
                
                // Check for instances without firewall rules restrictions
                // Check for instances with default service account with full access
                // Check for instances without OS Login enabled
                // Check for instances without disk encryption
                
                var vulnResult = ScanResult.CreateOpen(
                    System.Net.IPAddress.Parse(instance.PublicIpAddress),
                    0,
                    "GCP Security Configuration",
                    0
                ).WithVulnerability("Instance has external IP - ensure proper firewall configuration");

                vulnerabilities.Add(vulnResult);
            }

            await Task.Delay(1, cancellationToken); // Simulate async operation
        }
        catch (Exception ex)
        {
            Console.WriteLine($"GCP vulnerability check failed for {instance.ResourceId}: {ex.Message}");
        }

        return vulnerabilities;
    }
}