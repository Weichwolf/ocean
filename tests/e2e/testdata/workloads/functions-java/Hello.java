package ocean.fixture;

import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

public final class Hello {
    @FunctionName("hello")
    public HttpResponseMessage run(
        @HttpTrigger(name = "request", methods = {HttpMethod.GET}, authLevel = AuthorizationLevel.FUNCTION, route = "hello")
        HttpRequestMessage<Optional<String>> request,
        ExecutionContext context
    ) {
        String version = System.getenv().getOrDefault("OCEAN_FIXTURE_VERSION", "v1");
        String setting = System.getenv().getOrDefault("OCEAN_SETTING", "unset");
        context.getLogger().info("ocean Java fixture invoked");
        if ("source".equals(request.getQueryParameters().get("mode"))) {
            return observeSource(request);
        }
        return request.createResponseBuilder(HttpStatus.OK)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body("java:" + version + ":" + setting + "\n")
            .build();
    }

    private HttpResponseMessage observeSource(HttpRequestMessage<Optional<String>> request) {
        String endpoint = System.getenv("OCEAN_OBSERVER_URL");
        if (endpoint == null) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST).build();
        }
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
            HttpRequest probe = HttpRequest.newBuilder(URI.create(endpoint)).timeout(Duration.ofSeconds(3)).build();
            HttpResponse<String> result = client.send(probe, HttpResponse.BodyHandlers.ofString());
            return request.createResponseBuilder(result.statusCode() == 200 ? HttpStatus.OK : HttpStatus.BAD_GATEWAY)
                .header("Content-Type", "text/plain; charset=utf-8").body(result.body()).build();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return request.createResponseBuilder(HttpStatus.SERVICE_UNAVAILABLE).build();
        } catch (Exception error) {
            return request.createResponseBuilder(HttpStatus.BAD_GATEWAY).build();
        }
    }
}
