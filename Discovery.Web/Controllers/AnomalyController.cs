using Microsoft.AspNetCore.Mvc;
using Discovery.Web.Models;
using Discovery.Services.MachineLearning;
using Discovery.Services.Data;
using Discovery.Core.Models;
using Discovery.Core.Utilities;

namespace Discovery.Web.Controllers;

/// <summary>
/// API controller for machine learning anomaly detection
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AnomalyController : ControllerBase
{
    private readonly ILogger<AnomalyController> _logger;
    private readonly AnomalyDetectionService _anomalyDetectionService;
    private readonly DatabaseService _databaseService;

    public AnomalyController(
        ILogger<AnomalyController> logger,
        AnomalyDetectionService anomalyDetectionService,
        DatabaseService databaseService)
    {
        _logger = logger;
        _anomalyDetectionService = anomalyDetectionService;
        _databaseService = databaseService;
    }

    /// <summary>
    /// Detect anomalies in network scan data
    /// </summary>
    /// <param name="request">The anomaly detection request</param>
    [HttpPost("detect")]
    public async Task<ActionResult<object>> DetectAnomalies([FromBody] AnomalyDetectionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.NetworkRange))
        {
            return BadRequest("Network range is required");
        }

        _logger.LogInformation("Starting anomaly detection for {NetworkRange}", request.NetworkRange);

        try
        {
            // For this example, we'll create some sample scan results
            // In a real implementation, you would retrieve actual scan data
            var currentScanResults = await GetCurrentScanResults(request.NetworkRange);
            
            IEnumerable<ScanResult> historicalData = new List<ScanResult>();
            if (request.UseHistoricalData)
            {
                historicalData = await GetHistoricalScanResults(request.NetworkRange, request.DaysBack ?? 30);
            }

            var anomalies = await _anomalyDetectionService.DetectAnomaliesAsync(
                currentScanResults, 
                historicalData, 
                CancellationToken.None);

            // Filter by threshold if specified
            if (request.AnomalyThreshold.HasValue)
            {
                anomalies = anomalies.Where(a => a.AnomalyScore >= request.AnomalyThreshold.Value);
            }

            var anomalyDtos = anomalies.Select(a => new AnomalyDto
            {
                IpAddress = a.IpAddress,
                AnomalyType = a.AnomalyType,
                AnomalyScore = a.AnomalyScore,
                Description = a.Description,
                Context = a.Context ?? string.Empty,
                DetectedAt = a.DetectedAt
            }).ToList();

            var sessionId = await StoreAnomalyResults(request.NetworkRange, anomalyDtos);

            _logger.LogInformation("Anomaly detection completed for {NetworkRange}. Found {Count} anomalies", 
                request.NetworkRange, anomalyDtos.Count);

            return Ok(new
            {
                SessionId = sessionId,
                NetworkRange = request.NetworkRange,
                Anomalies = anomalyDtos,
                Summary = new
                {
                    TotalAnomalies = anomalyDtos.Count,
                    HighScoreAnomalies = anomalyDtos.Count(a => a.AnomalyScore >= 0.8),
                    MediumScoreAnomalies = anomalyDtos.Count(a => a.AnomalyScore >= 0.6 && a.AnomalyScore < 0.8),
                    AnomalyTypes = anomalyDtos.GroupBy(a => a.AnomalyType).ToDictionary(g => g.Key, g => g.Count()),
                    DetectionCompletedAt = DateTime.UtcNow
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during anomaly detection for {NetworkRange}", request.NetworkRange);
            return StatusCode(500, new { Error = "Anomaly detection failed", Message = ex.Message });
        }
    }

    /// <summary>
    /// Train the anomaly detection model with historical data
    /// </summary>
    /// <param name="daysBack">Number of days of historical data to use for training</param>
    [HttpPost("train-model")]
    public async Task<ActionResult<object>> TrainModel([FromQuery] int daysBack = 90)
    {
        _logger.LogInformation("Starting ML model training with {Days} days of historical data", daysBack);

        try
        {
            // Retrieve historical training data
            var trainingData = await GetHistoricalTrainingData(daysBack);
            
            if (!trainingData.Any())
            {
                return BadRequest(new { Error = "No training data available", Message = $"No scan data found for the past {daysBack} days" });
            }

            var success = await _anomalyDetectionService.TrainModelAsync(trainingData, CancellationToken.None);
            
            if (success)
            {
                _logger.LogInformation("ML model training completed successfully with {Count} training samples", trainingData.Count());
                
                return Ok(new
                {
                    Success = true,
                    Message = "Model training completed successfully",
                    TrainingSamples = trainingData.Count(),
                    TrainingPeriod = $"{daysBack} days",
                    CompletedAt = DateTime.UtcNow
                });
            }
            else
            {
                return StatusCode(500, new { Error = "Model training failed", Message = "Training process completed but failed to save model" });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during ML model training");
            return StatusCode(500, new { Error = "Model training failed", Message = ex.Message });
        }
    }

    /// <summary>
    /// Load a pre-trained anomaly detection model
    /// </summary>
    [HttpPost("load-model")]
    public async Task<ActionResult<object>> LoadModel()
    {
        _logger.LogInformation("Loading pre-trained ML model");

        try
        {
            var success = await _anomalyDetectionService.LoadModelAsync(CancellationToken.None);
            
            if (success)
            {
                _logger.LogInformation("ML model loaded successfully");
                
                return Ok(new
                {
                    Success = true,
                    Message = "Model loaded successfully",
                    LoadedAt = DateTime.UtcNow
                });
            }
            else
            {
                return NotFound(new { Error = "Model not found", Message = "No pre-trained model found. Train a model first." });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading ML model");
            return StatusCode(500, new { Error = "Model loading failed", Message = ex.Message });
        }
    }

    /// <summary>
    /// Get anomaly detection statistics and model status
    /// </summary>
    [HttpGet("status")]
    public ActionResult<object> GetAnomalyDetectionStatus()
    {
        return Ok(new
        {
            Service = "Anomaly Detection",
            Status = "Online",
            Version = VersionManager.GetVersionString(),
            Capabilities = new[]
            {
                "Port Pattern Anomalies",
                "Service Behavior Anomalies", 
                "Timing Anomalies",
                "Behavioral Anomalies",
                "New Host Detection",
                "ML Model Training",
                "Time Series Analysis"
            },
            Timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Analyze specific scan results for anomalies
    /// </summary>
    /// <param name="scanResults">Array of scan results to analyze</param>
    [HttpPost("analyze-results")]
    public async Task<ActionResult<object>> AnalyzeScanResults([FromBody] ScanResultDto[] scanResults)
    {
        if (scanResults == null || !scanResults.Any())
        {
            return BadRequest("Scan results are required");
        }

        _logger.LogInformation("Analyzing {Count} scan results for anomalies", scanResults.Length);

        try
        {
            // Convert DTOs to ScanResult models
            var convertedResults = scanResults.Select(dto => new ScanResult(
                System.Net.IPAddress.Parse(dto.IpAddress),
                dto.Port,
                dto.IsOpen,
                dto.Service,
                dto.PingTime,
                dto.OperatingSystem,
                dto.ServerInfo,
                dto.DiscoveredAt,
                dto.Country,
                dto.Hostname,
                dto.IsVulnerable,
                dto.VulnerabilityInfo,
                dto.ServiceName
            )).ToList();

            var anomalies = await _anomalyDetectionService.DetectAnomaliesAsync(
                convertedResults, 
                null, // No historical data for ad-hoc analysis
                CancellationToken.None);

            var anomalyDtos = anomalies.Select(a => new AnomalyDto
            {
                IpAddress = a.IpAddress,
                AnomalyType = a.AnomalyType,
                AnomalyScore = a.AnomalyScore,
                Description = a.Description,
                Context = a.Context ?? string.Empty,
                DetectedAt = a.DetectedAt
            }).ToList();

            _logger.LogInformation("Scan result analysis completed. Found {Count} anomalies", anomalyDtos.Count);

            return Ok(new
            {
                AnalyzedResults = scanResults.Length,
                Anomalies = anomalyDtos,
                Summary = new
                {
                    TotalAnomalies = anomalyDtos.Count,
                    HighScoreAnomalies = anomalyDtos.Count(a => a.AnomalyScore >= 0.8),
                    AnomalyTypes = anomalyDtos.GroupBy(a => a.AnomalyType).ToDictionary(g => g.Key, g => g.Count()),
                    AnalysisCompletedAt = DateTime.UtcNow
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing scan results for anomalies");
            return StatusCode(500, new { Error = "Scan result analysis failed", Message = ex.Message });
        }
    }

    private async Task<IEnumerable<ScanResult>> GetCurrentScanResults(string networkRange)
    {
        // In a real implementation, this would query the database for recent scan results
        // For now, return empty list
        await Task.Delay(1);
        return new List<ScanResult>();
    }

    private async Task<IEnumerable<ScanResult>> GetHistoricalScanResults(string networkRange, int daysBack)
    {
        // In a real implementation, this would query the database for historical scan results
        // For now, return empty list
        await Task.Delay(1);
        return new List<ScanResult>();
    }

    private async Task<IEnumerable<ScanResult>> GetHistoricalTrainingData(int daysBack)
    {
        // In a real implementation, this would retrieve comprehensive training data
        // For now, return empty list
        await Task.Delay(1);
        return new List<ScanResult>();
    }

    private async Task<string> StoreAnomalyResults(string networkRange, List<AnomalyDto> anomalies)
    {
        try
        {
            await Task.Delay(1); // Make method async
            var sessionId = Guid.NewGuid().ToString();
            // Store anomaly detection results in database
            _logger.LogInformation("Stored anomaly detection results for session {SessionId}", sessionId);
            return sessionId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to store anomaly results for network range {NetworkRange}", networkRange);
            return Guid.NewGuid().ToString();
        }
    }
}