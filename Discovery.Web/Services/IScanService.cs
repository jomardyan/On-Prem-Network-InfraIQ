using Discovery.Web.Models;
using System.Threading.Tasks;

namespace Discovery.Web.Services
{
    public interface IScanService
    {
        Task<string> StartScanAsync(ScanRequest request);
        Task StopScanAsync(string scanId);
        object GetScanStatus(string scanId);
    }
}
