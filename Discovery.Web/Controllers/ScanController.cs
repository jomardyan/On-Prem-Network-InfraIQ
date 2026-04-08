using Discovery.Web.Models;
using Discovery.Web.Services;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace Discovery.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ScanController : ControllerBase
    {
        private readonly IScanService _scanService;

        public ScanController(IScanService scanService)
        {
            _scanService = scanService;
        }

        [HttpPost]
        public async Task<IActionResult> StartScan([FromBody] ScanRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Target))
            {
                return BadRequest("Target is required.");
            }

            var scanId = await _scanService.StartScanAsync(request);
            return Accepted(new { scanId });
        }

        [HttpDelete("{scanId}")]
        public async Task<IActionResult> StopScan(string scanId)
        {
            await _scanService.StopScanAsync(scanId);
            return Ok();
        }

        [HttpGet("{scanId}")]
        public IActionResult GetScanStatus(string scanId)
        {
            var status = _scanService.GetScanStatus(scanId);
            return Ok(status);
        }
    }
}
