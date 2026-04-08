using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Messaging.ServiceBus;
using Discovery.Core.Models;
using System.Text.Json;
using Azure.Core;

namespace Discovery.Services.Cloud;

/// <summary>
/// Azure cloud integration service for discovery and storage operations.
/// </summary>
public class AzureCloudService
{
    private readonly ArmClient _armClient;
    private readonly BlobServiceClient _blobServiceClient;
    private readonly ServiceBusClient _serviceBusClient;
    private readonly string _containerName;
    private readonly string _serviceBusTopicName;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureCloudService"/> class.
    /// </summary>
    /// <param name="armClient">The Azure Resource Manager client.</param>
    /// <param name="blobServiceClient">The Blob storage client.</param>
    /// <param name="serviceBusClient">The Service Bus client.</param>
    /// <param name="containerName">The blob container name for storing results.</param>
    /// <param name="serviceBusTopicName">The Service Bus topic name for notifications.</param>
    public AzureCloudService(
        ArmClient armClient,
        BlobServiceClient blobServiceClient,
        ServiceBusClient serviceBusClient,
        string containerName,
        string serviceBusTopicName)
    {
        _armClient = armClient ?? throw new ArgumentNullException(nameof(armClient));
        _blobServiceClient = blobServiceClient ?? throw new ArgumentNullException(nameof(blobServiceClient));
        _serviceBusClient = serviceBusClient ?? throw new ArgumentNullException(nameof(serviceBusClient));
        _containerName = containerName ?? throw new ArgumentNullException(nameof(containerName));
        _serviceBusTopicName = serviceBusTopicName ?? throw new ArgumentNullException(nameof(serviceBusTopicName));
    }

    /// <summary>
    /// Discovers Azure Virtual Machines across subscriptions and resource groups.
    /// </summary>
    /// <param name="subscriptionIds">The subscription IDs to scan. If null, scans all accessible subscriptions.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of discovered cloud resources.</returns>
    public async Task<IEnumerable<CloudResourceEntity>> DiscoverVirtualMachinesAsync(
        IEnumerable<string>? subscriptionIds = null,
        CancellationToken cancellationToken = default)
    {
        var resources = new List<CloudResourceEntity>();

        try
        {
            // Get subscriptions to scan
            var subscriptions = subscriptionIds?.Select(id => _armClient.GetSubscriptionResource(
                Azure.ResourceManager.Resources.SubscriptionResource.CreateResourceIdentifier(id)))
                ?? _armClient.GetSubscriptions();

            foreach (var subscription in subscriptions)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    Console.WriteLine($"Scanning subscription: {subscription.Data.DisplayName}");

                    // Get all VMs in the subscription
                    var vms = subscription.GetVirtualMachines();

                    foreach (var vm in vms)
                    {
                        if (cancellationToken.IsCancellationRequested) break;

                        try
                        {
                            var vmData = vm.Data;
                            var location = vmData.Location.ToString();

                            // Get network interfaces to find IP addresses
                            var ipAddresses = await GetVmIpAddressesAsync(vm, cancellationToken);

                            var resource = new CloudResourceEntity
                            {
                                CloudProvider = "Azure",
                                Region = location,
                                ResourceType = "VirtualMachine",
                                ResourceId = vmData.Name,
                                PublicIpAddress = ipAddresses.PublicIp,
                                PrivateIpAddress = ipAddresses.PrivateIp,
                                ResourceName = vmData.Name,
                                Status = vmData.ProvisioningState ?? "Unknown",
                                DiscoveredAt = DateTime.UtcNow,
                                Metadata = JsonSerializer.Serialize(new
                                {
                                    ResourceGroupName = GetResourceGroupName(vm.Id),
                                    VmSize = vmData.HardwareProfile?.VmSize,
                                    OsType = vmData.StorageProfile?.OSDisk?.OSType?.ToString(),
                                    OsVersion = vmData.StorageProfile?.ImageReference?.Sku,
                                    SubscriptionId = subscription.Data.SubscriptionId,
                                    Tags = vmData.Tags,
                                    PowerState = await GetVmPowerStateAsync(vm, cancellationToken)
                                })
                            };

                            resources.Add(resource);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to process VM {vm.Data.Name}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to scan subscription {subscription.Data.DisplayName}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Azure VM discovery failed: {ex.Message}");
        }

        return resources;
    }

    /// <summary>
    /// Scans discovered Azure VMs for open ports and vulnerabilities.
    /// </summary>
    /// <param name="vms">The Azure VMs to scan.</param>
    /// <param name="ports">The ports to scan.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan results.</returns>
    public async Task<IEnumerable<ScanResult>> ScanVirtualMachinesAsync(
        IEnumerable<CloudResourceEntity> vms,
        IEnumerable<int> ports,
        CancellationToken cancellationToken = default)
    {
        var results = new List<ScanResult>();
        var portScanner = new Services.Scanning.PortScanner();

        foreach (var vm in vms)
        {
            if (cancellationToken.IsCancellationRequested) break;

            var targetIp = !string.IsNullOrEmpty(vm.PublicIpAddress) 
                ? vm.PublicIpAddress 
                : vm.PrivateIpAddress;

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
                        ).WithServerInfo($"Azure VM: {vm.ResourceId}", "Azure VM");

                        results.Add(scanResult);
                    }
                }

                // Add Azure-specific vulnerability checks
                var azureVulns = await CheckAzureSpecificVulnerabilitiesAsync(vm, cancellationToken);
                results.AddRange(azureVulns);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to scan VM {vm.ResourceId}: {ex.Message}");
            }
        }

        return results;
    }

    /// <summary>
    /// Stores scan results to Azure Blob Storage.
    /// </summary>
    /// <param name="sessionId">The scan session ID.</param>
    /// <param name="results">The scan results to store.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The blob name where results were stored.</returns>
    public async Task<string> StoreResultsToBlobAsync(
        Guid sessionId,
        IEnumerable<ScanResult> results,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
            
            // Ensure container exists
            await containerClient.CreateIfNotExistsAsync(cancellationToken: cancellationToken);

            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss");
            var blobName = $"scan-results/{sessionId}/{timestamp}.json";

            var resultsJson = JsonSerializer.Serialize(results, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            var blobClient = containerClient.GetBlobClient(blobName);
            
            using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(resultsJson));
            
            var blobHttpHeaders = new BlobHttpHeaders
            {
                ContentType = "application/json"
            };

            var metadata = new Dictionary<string, string>
            {
                ["SessionId"] = sessionId.ToString(),
                ["Timestamp"] = timestamp,
                ["ResultCount"] = results.Count().ToString()
            };

            await blobClient.UploadAsync(
                stream, 
                new BlobUploadOptions 
                { 
                    HttpHeaders = blobHttpHeaders,
                    Metadata = metadata
                }, 
                cancellationToken);

            return blobName;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to store results to Azure Blob: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Retrieves scan results from Azure Blob Storage.
    /// </summary>
    /// <param name="blobName">The blob name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The scan results.</returns>
    public async Task<IEnumerable<ScanResult>> RetrieveResultsFromBlobAsync(
        string blobName,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
            var blobClient = containerClient.GetBlobClient(blobName);

            var response = await blobClient.DownloadContentAsync(cancellationToken);
            var resultsJson = response.Value.Content.ToString();

            var results = JsonSerializer.Deserialize<IEnumerable<ScanResult>>(resultsJson);
            return results ?? Enumerable.Empty<ScanResult>();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to retrieve results from Azure Blob: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Sends notification about scan completion via Service Bus.
    /// </summary>
    /// <param name="sessionId">The scan session ID.</param>
    /// <param name="summary">The scan summary.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The message sequence number.</returns>
    public async Task<long> SendScanNotificationAsync(
        Guid sessionId,
        ScanSummary summary,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var sender = _serviceBusClient.CreateSender(_serviceBusTopicName);

            var messageBody = JsonSerializer.Serialize(new
            {
                SessionId = sessionId,
                Summary = summary,
                Timestamp = DateTime.UtcNow
            });

            var message = new ServiceBusMessage(messageBody)
            {
                Subject = $"On-Prem Network InfraIQ - Scan Completed: {sessionId}",
                MessageId = Guid.NewGuid().ToString(),
                ApplicationProperties =
                {
                    ["SessionId"] = sessionId.ToString(),
                    ["ScanType"] = summary.ScanType,
                    ["VulnerabilitiesFound"] = summary.VulnerabilitiesFound,
                    ["ActiveHosts"] = summary.ActiveHosts
                }
            };

            await sender.SendMessageAsync(message, cancellationToken);
            return 1; // Simplified return since sequence number isn't available on send
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to send Service Bus notification: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets the IP addresses for a virtual machine.
    /// </summary>
    private async Task<(string? PublicIp, string? PrivateIp)> GetVmIpAddressesAsync(
        VirtualMachineResource vm,
        CancellationToken cancellationToken)
    {
        try
        {
            string? publicIp = null;
            string? privateIp = null;

            // Get network interfaces for the VM
            foreach (var nicRef in vm.Data.NetworkProfile?.NetworkInterfaces ?? Enumerable.Empty<VirtualMachineNetworkInterfaceReference>())
            {
                try
                {
                    // In a real implementation, you would resolve the network interface
                    // and get its IP configurations to find public and private IPs
                    // For now, we'll return placeholder values
                    
                    await Task.Delay(1, cancellationToken); // Simulate async operation
                    
                    // This would involve calling Azure APIs to get the actual IP addresses
                    // privateIp = "10.0.0.x"; // Would be retrieved from NIC
                    // publicIp = "x.x.x.x";   // Would be retrieved from public IP resource
                }
                catch
                {
                    // Failed to get IP addresses for this NIC
                }
            }

            return (publicIp, privateIp);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Gets the power state of a virtual machine.
    /// </summary>
    private async Task<string> GetVmPowerStateAsync(VirtualMachineResource vm, CancellationToken cancellationToken)
    {
        try
        {
            var instanceView = await vm.GetAsync(cancellationToken: cancellationToken);
            var powerState = instanceView.Value.Data.InstanceView?.Statuses?
                .FirstOrDefault(s => s.Code?.StartsWith("PowerState/") == true);
            
            return powerState?.DisplayStatus ?? "Unknown";
        }
        catch
        {
            return "Unknown";
        }
    }

    /// <summary>
    /// Extracts the resource group name from a resource ID.
    /// </summary>
    private string GetResourceGroupName(ResourceIdentifier resourceId)
    {
        return resourceId.ResourceGroupName ?? "Unknown";
    }

    /// <summary>
    /// Performs Azure-specific vulnerability checks.
    /// </summary>
    private async Task<IEnumerable<ScanResult>> CheckAzureSpecificVulnerabilitiesAsync(
        CloudResourceEntity vm,
        CancellationToken cancellationToken)
    {
        var vulnerabilities = new List<ScanResult>();

        try
        {
            // Check for VMs with public IPs
            if (!string.IsNullOrEmpty(vm.PublicIpAddress))
            {
                var metadata = JsonSerializer.Deserialize<dynamic>(vm.Metadata ?? "{}");
                
                // Check for VMs without Network Security Groups
                // This would require additional Azure API calls to check NSG configurations

                // Check for VMs with overly permissive NSG rules
                // Check for VMs without Azure Security Center monitoring
                // Check for VMs without disk encryption
                
                var vulnResult = ScanResult.CreateOpen(
                    System.Net.IPAddress.Parse(vm.PublicIpAddress),
                    0,
                    "Azure Security Configuration",
                    0
                ).WithVulnerability("VM has public IP - ensure proper security group configuration");

                vulnerabilities.Add(vulnResult);
            }

            await Task.Delay(1, cancellationToken); // Simulate async operation
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Azure vulnerability check failed for {vm.ResourceId}: {ex.Message}");
        }

        return vulnerabilities;
    }
}