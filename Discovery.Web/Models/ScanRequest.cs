namespace Discovery.Web.Models
{
    public class ScanRequest
    {
        public string Target { get; set; } = string.Empty;
        public int[]? Ports { get; set; }
    }
}
