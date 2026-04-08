using Discovery.Services.Scanning;
using Discovery.Services.Security;
using Discovery.Services.MachineLearning;
using Discovery.Services.Data;
using Discovery.Core.Data;
using Discovery.Core.Utilities;
using Microsoft.EntityFrameworkCore;
using Discovery.Web.Hubs;
using Discovery.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddControllersWithViews();
builder.Services.AddSignalR();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        builder =>
        {
            builder.AllowAnyOrigin()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
        });
});

// Add database context
builder.Services.AddDbContext<NetworkDiscoveryDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? 
                      "Data Source=networkdiscovery.db"));

// Register Core Scanning Services (these should work)
builder.Services.AddScoped<PortScanner>();
builder.Services.AddScoped<AdvancedPortScanner>();
builder.Services.AddScoped<IPv6Scanner>();
builder.Services.AddScoped<IPv6NeighborDiscoveryService>();
builder.Services.AddScoped<CidrScanner>();

// Register Basic Security Services (these should work)
builder.Services.AddScoped<VulnerabilityScanner>();
builder.Services.AddScoped<SslCertificateChecker>();
builder.Services.AddScoped<PortSecurityAuditor>();

// Machine Learning Services
builder.Services.AddScoped<AnomalyDetectionService>();

// Database Services
builder.Services.AddScoped<DatabaseService>();

// Register ScanService for real-time scans
builder.Services.AddScoped<IScanService, ScanService>();

// Skip the problematic services for now - we'll implement them as basic mock services
// These cause dependency injection issues:
// - AdvancedVulnerabilityScanner (needs IScanner)
// - ComprehensiveSecurityScanner (needs IScanner)
// - Cloud services (need external dependencies)

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() 
    { 
        Title = VersionManager.GetProductName() + " API", 
        Version = VersionManager.GetApiVersionString(),
        Description = VersionManager.GetProductDescription() + " API with advanced ML anomaly detection, IPv6 support, and enhanced capabilities"
    });
    
    // Include XML comments for better API documentation
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

var app = builder.Build();

// Initialize database (commented out for now to avoid issues during demo)
// using (var scope = app.Services.CreateScope())
// {
//     var dbService = scope.ServiceProvider.GetRequiredService<DatabaseService>();
//     await dbService.InitializeDatabaseAsync();
// }

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", VersionManager.GetProductName() + " API " + VersionManager.GetApiVersionString());
        c.RoutePrefix = "swagger";
        c.DisplayRequestDuration();
        c.EnableDeepLinking();
        c.EnableFilter();
    });
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();

app.UseCors("AllowAll");

// Map MVC routes for dashboard
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Dashboard}/{action=Index}/{id?}");

// Map API controllers
app.MapControllers();

// Map SignalR hubs (for real-time updates)
app.MapHub<ScanHub>("/scanhub");

app.Run();

// Make Program accessible for testing
public partial class Program { }
