using System.Net;
using Discovery.Web.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Discovery.Tests.Security;

public class OperatorAccessTests
{
    [Theory]
    [InlineData("127.0.0.1", "localhost:5275", null, null, true)]
    [InlineData("::1", "[::1]:5275", null, null, true)]
    [InlineData("::ffff:127.0.0.1", "localhost:5275", null, null, true)]
    [InlineData("127.0.0.1", "localhost:5275", "http://localhost:5275", null, true)]
    [InlineData("127.0.0.1", "localhost:5275", "https://attacker.example", null, false)]
    [InlineData("127.0.0.1", "localhost:5275", "null", null, false)]
    [InlineData("127.0.0.1", "attacker.example", "http://attacker.example", null, false)]
    [InlineData("192.0.2.1", "localhost:5275", null, null, false)]
    [InlineData("192.0.2.1", "infra.example", null, "wrong-key", false)]
    [InlineData("192.0.2.1", "infra.example", null, "local-test-key", true)]
    [InlineData("192.0.2.1", "infra.example", "http://infra.example", "local-test-key", true)]
    [InlineData("192.0.2.1", "infra.example", "http://attacker.example", "local-test-key", false)]
    public async Task GuardProtectsOperatorBoundary(string peer, string host, string? origin, string? key, bool allowed)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString(host);
        context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        context.Response.Body = new MemoryStream();
        if (origin is not null) context.Request.Headers.Origin = origin;
        if (key is not null) context.Request.Headers["X-InfraIQ-Api-Key"] = key;
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Security:ApiKey"] = "local-test-key" }).Build();
        var called = false;
        var middleware = new OperatorAccessMiddleware(_ => { called = true; return Task.CompletedTask; }, config);
        await middleware.InvokeAsync(context);
        Assert.Equal(allowed, called);
        Assert.Equal(allowed ? 200 : 403, context.Response.StatusCode);
    }

    [Fact]
    public async Task RemoteAccessFailsClosedWithoutConfiguredKey()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("infra.example");
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.1");
        context.Request.Headers["X-InfraIQ-Api-Key"] = "local-test-key";
        context.Response.Body = new MemoryStream();
        var middleware = new OperatorAccessMiddleware(_ => throw new Exception("Unauthenticated request passed"), new ConfigurationBuilder().Build());
        await middleware.InvokeAsync(context);
        Assert.Equal(403, context.Response.StatusCode);
    }
}
