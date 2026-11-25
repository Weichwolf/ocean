using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Hosting;

new HostBuilder().ConfigureFunctionsWorkerDefaults().Build().Run();

public sealed class Hello
{
    [Function("hello")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "hello")] HttpRequestData request)
    {
        var reply = request.CreateResponse(HttpStatusCode.OK);
        reply.Headers.Add("Content-Type", "text/plain; charset=utf-8");
        await reply.WriteStringAsync("dotnet:" + (Environment.GetEnvironmentVariable("OCEAN_SETTING") ?? "unset") + "\n");
        return reply;
    }
}
