using Microsoft.AspNetCore.Mvc;

namespace Discovery.Web.Controllers;

/// <summary>
/// Controller for serving the dashboard web interface
/// </summary>
public class DashboardController : Controller
{
    /// <summary>
    /// Serve the main dashboard page
    /// </summary>
    public IActionResult Index()
    {
        return View();
    }

    /// <summary>
    /// Serve the network scanner page
    /// </summary>
    public IActionResult Scanner()
    {
        return View();
    }

    /// <summary>
    /// Serve the results page
    /// </summary>
    public IActionResult Results()
    {
        return View();
    }

    public IActionResult Scan()
    {
        return View();
    }
}