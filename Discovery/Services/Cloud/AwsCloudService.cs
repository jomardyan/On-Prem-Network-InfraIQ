using Amazon.EC2;
using Amazon.EC2.Model;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using Discovery.Core.Models;
using System.Text.Json;

namespace Discovery.Services.Cloud;

/// <summary>
/// AWS cloud integration service for discovery and storage operations.
/// </summary>
public class AwsCloudService
{
    private readonly IAmazonEC2 _ec2Client;
    private readonly IAmazonS3 _s3Client;
    private readonly IAmazonSimpleNotificationService _snsClient;
    private readonly string _s3BucketName;
    private readonly string _snsTopicArn;

    /// <summary>
    /// Initializes a new instance of the <see cref="AwsCloudService"/> class.
    /// </summary>
    /// <param name="ec2Client">The EC2 client.</param>
    /// <param name="s3Client">The S3 client.</param>
    /// <param name="snsClient">The SNS client.</param>
    /// <param name="s3BucketName">The S3 bucket name for storing results.</param>
    /// <param name="snsTopicArn">The SNS topic ARN for notifications.</param>
    public AwsCloudService(
        IAmazonEC2 ec2Client,
        IAmazonS3 s3Client,
        IAmazonSimpleNotificationService snsClient,
        string s3BucketName,
        string snsTopicArn)
    {
        _ec2Client = ec2Client ?? throw new ArgumentNullException(nameof(ec2Client));
        _s3Client = s3Client ?? throw new ArgumentNullException(nameof(s3Client));
        _snsClient = snsClient ?? throw new ArgumentNullException(nameof(snsClient));
        _s3BucketName = s3BucketName ?? throw new ArgumentNullException(nameof(s3BucketName));
        _snsTopicArn = snsTopicArn ?? throw new ArgumentNullException(nameof(snsTopicArn));
    }

    /// <summary>
    /// Discovers EC2 instances in the specified regions.
    /// </summary>
    /// <param name="regions">The AWS regions to scan. If null, scans all regions.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of discovered cloud resources.</returns>
    public async Task<IEnumerable<CloudResourceEntity>> DiscoverEC2InstancesAsync(
        IEnumerable<string>? regions = null,
        CancellationToken cancellationToken = default)
    {
        var resources = new List<CloudResourceEntity>();

        try
        {
            // If no regions specified, get all available regions
            if (regions == null)
            {
                var regionsResponse = await _ec2Client.DescribeRegionsAsync(cancellationToken);
                regions = regionsResponse.Regions.Select(r => r.RegionName);
            }

            foreach (var region in regions)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    // Create region-specific EC2 client
                    var regionConfig = new AmazonEC2Config { RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(region) };
                    using var regionClient = new AmazonEC2Client(regionConfig);

                    var instancesResponse = await regionClient.DescribeInstancesAsync(cancellationToken);

                    foreach (var reservation in instancesResponse.Reservations)
                    {
                        foreach (var instance in reservation.Instances)
                        {
                            // Skip terminated instances
                            if (instance.State.Name == InstanceStateName.Terminated) continue;

                            var resource = new CloudResourceEntity
                            {
                                CloudProvider = "AWS",
                                Region = region,
                                ResourceType = "EC2Instance",
                                ResourceId = instance.InstanceId,
                                PublicIpAddress = instance.PublicIpAddress,
                                PrivateIpAddress = instance.PrivateIpAddress,
                                ResourceName = GetInstanceName(instance),
                                Status = instance.State.Name.Value,
                                DiscoveredAt = DateTime.UtcNow,
                                Metadata = JsonSerializer.Serialize(new
                                {
                                    InstanceType = instance.InstanceType.Value,
                                    LaunchTime = instance.LaunchTime,
                                    VpcId = instance.VpcId,
                                    SubnetId = instance.SubnetId,
                                    SecurityGroups = instance.SecurityGroups.Select(sg => new { sg.GroupId, sg.GroupName }),
                                    Tags = instance.Tags.ToDictionary(t => t.Key, t => t.Value)
                                })
                            };

                            resources.Add(resource);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to discover instances in region {region}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"AWS EC2 discovery failed: {ex.Message}");
        }

        return resources;
    }

    /// <summary>
    /// Scans discovered EC2 instances for open ports and vulnerabilities.
    /// </summary>
    /// <param name="instances">The EC2 instances to scan.</param>
    /// <param name="ports">The ports to scan.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A collection of scan results.</returns>
    public async Task<IEnumerable<ScanResult>> ScanEC2InstancesAsync(
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
                        ).WithServerInfo($"AWS EC2 Instance: {instance.ResourceId}", "AWS EC2");

                        results.Add(scanResult);
                    }
                }

                // Add AWS-specific vulnerability checks
                var awsVulns = await CheckAwsSpecificVulnerabilitiesAsync(instance, cancellationToken);
                results.AddRange(awsVulns);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to scan instance {instance.ResourceId}: {ex.Message}");
            }
        }

        return results;
    }

    /// <summary>
    /// Stores scan results to S3.
    /// </summary>
    /// <param name="sessionId">The scan session ID.</param>
    /// <param name="results">The scan results to store.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The S3 object key where results were stored.</returns>
    public async Task<string> StoreResultsToS3Async(
        Guid sessionId,
        IEnumerable<ScanResult> results,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss");
            var objectKey = $"scan-results/{sessionId}/{timestamp}.json";

            var resultsJson = JsonSerializer.Serialize(results, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            var putRequest = new PutObjectRequest
            {
                BucketName = _s3BucketName,
                Key = objectKey,
                ContentBody = resultsJson,
                ContentType = "application/json",
                Metadata =
                {
                    ["SessionId"] = sessionId.ToString(),
                    ["Timestamp"] = timestamp,
                    ["ResultCount"] = results.Count().ToString()
                }
            };

            await _s3Client.PutObjectAsync(putRequest, cancellationToken);
            return objectKey;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to store results to S3: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Retrieves scan results from S3.
    /// </summary>
    /// <param name="objectKey">The S3 object key.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The scan results.</returns>
    public async Task<IEnumerable<ScanResult>> RetrieveResultsFromS3Async(
        string objectKey,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var getRequest = new GetObjectRequest
            {
                BucketName = _s3BucketName,
                Key = objectKey
            };

            using var response = await _s3Client.GetObjectAsync(getRequest, cancellationToken);
            using var streamReader = new StreamReader(response.ResponseStream);
            var resultsJson = await streamReader.ReadToEndAsync();

            var results = JsonSerializer.Deserialize<IEnumerable<ScanResult>>(resultsJson);
            return results ?? Enumerable.Empty<ScanResult>();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to retrieve results from S3: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Sends notification about scan completion.
    /// </summary>
    /// <param name="sessionId">The scan session ID.</param>
    /// <param name="summary">The scan summary.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The message ID.</returns>
    public async Task<string> SendScanNotificationAsync(
        Guid sessionId,
        ScanSummary summary,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var message = JsonSerializer.Serialize(new
            {
                SessionId = sessionId,
                Summary = summary,
                Timestamp = DateTime.UtcNow
            });

            var publishRequest = new PublishRequest
            {
                TopicArn = _snsTopicArn,
                Message = message,
                Subject = $"On-Prem Network InfraIQ - Scan Completed: {sessionId}"
            };

            var response = await _snsClient.PublishAsync(publishRequest, cancellationToken);
            return response.MessageId;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to send SNS notification: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets the instance name from tags or instance ID.
    /// </summary>
    private string GetInstanceName(Instance instance)
    {
        var nameTag = instance.Tags.FirstOrDefault(t => t.Key.Equals("Name", StringComparison.OrdinalIgnoreCase));
        return nameTag?.Value ?? instance.InstanceId;
    }

    /// <summary>
    /// Performs AWS-specific vulnerability checks.
    /// </summary>
    private async Task<IEnumerable<ScanResult>> CheckAwsSpecificVulnerabilitiesAsync(
        CloudResourceEntity instance,
        CancellationToken cancellationToken)
    {
        var vulnerabilities = new List<ScanResult>();

        try
        {
            // Check for instances with public IPs
            if (!string.IsNullOrEmpty(instance.PublicIpAddress))
            {
                var metadata = JsonSerializer.Deserialize<dynamic>(instance.Metadata ?? "{}");
                
                // Check for default security groups
                var hasDefaultSG = false; // This would be extracted from metadata
                if (hasDefaultSG)
                {
                    var vulnResult = ScanResult.CreateOpen(
                        System.Net.IPAddress.Parse(instance.PublicIpAddress),
                        0,
                        "AWS Security Group",
                        0
                    ).WithVulnerability("Instance uses default security group which may be overly permissive");

                    vulnerabilities.Add(vulnResult);
                }

                // Check for unrestricted SSH access (0.0.0.0/0 on port 22)
                // This would require detailed security group analysis

                // Check for instance metadata service v1 (IMDSv1) - security risk
                // This would require connecting to the instance and checking metadata service
            }

            await Task.Delay(1, cancellationToken); // Simulate async operation
        }
        catch (Exception ex)
        {
            Console.WriteLine($"AWS vulnerability check failed for {instance.ResourceId}: {ex.Message}");
        }

        return vulnerabilities;
    }
}

/// <summary>
/// Summary of a scan session.
/// </summary>
public class ScanSummary
{
    /// <summary>
    /// Gets or sets the total number of hosts scanned.
    /// </summary>
    public int TotalHosts { get; set; }

    /// <summary>
    /// Gets or sets the number of active hosts found.
    /// </summary>
    public int ActiveHosts { get; set; }

    /// <summary>
    /// Gets or sets the total number of open ports found.
    /// </summary>
    public int OpenPorts { get; set; }

    /// <summary>
    /// Gets or sets the number of vulnerabilities found.
    /// </summary>
    public int VulnerabilitiesFound { get; set; }

    /// <summary>
    /// Gets or sets the scan duration.
    /// </summary>
    public TimeSpan Duration { get; set; }

    /// <summary>
    /// Gets or sets the scan type.
    /// </summary>
    public string ScanType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the target that was scanned.
    /// </summary>
    public string Target { get; set; } = string.Empty;
}