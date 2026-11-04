using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Discovery.Web.Security;

/// <summary>Keep local operator workflows available and authenticate remote clients.</summary>
public sealed class OperatorAccessMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;

    public OperatorAccessMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _configuration = configuration;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!HasSameOrigin(context.Request) || (!IsLocalOperator(context) && !HasOperatorKey(context.Request)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Operator access denied.");
            return;
        }

        await _next(context);
    }

    private static bool IsLocalOperator(HttpContext context)
    {
        var address = context.Connection.RemoteIpAddress;
        if (address?.IsIPv4MappedToIPv6 == true)
            address = address.MapToIPv4();
        var host = context.Request.Host.Host.Trim('[', ']');
        var loopbackHost = string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(host, out var hostAddress) && IPAddress.IsLoopback(hostAddress));
        // Null peer addresses occur with in-process TestServer, not TCP clients.
        return loopbackHost && (address is null || IPAddress.IsLoopback(address));
    }

    private bool HasOperatorKey(HttpRequest request)
    {
        var expected = _configuration["Security:ApiKey"];
        var supplied = request.Headers["X-InfraIQ-Api-Key"];
        return !string.IsNullOrWhiteSpace(expected) && supplied.Count == 1
            && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(supplied.ToString()));
    }

    private static bool HasSameOrigin(HttpRequest request)
    {
        var header = request.Headers.Origin;
        if (header.Count == 0)
            return true; // Native API clients do not use browser Origin headers.
        return header.Count == 1
            && Uri.TryCreate(header.ToString(), UriKind.Absolute, out var origin)
            && origin.UserInfo.Length == 0 && origin.AbsolutePath == "/"
            && origin.Query.Length == 0 && origin.Fragment.Length == 0
            && Uri.TryCreate($"{request.Scheme}://{request.Host}", UriKind.Absolute, out var expected)
            && string.Equals(origin.GetLeftPart(UriPartial.Authority), expected.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase);
    }
}
