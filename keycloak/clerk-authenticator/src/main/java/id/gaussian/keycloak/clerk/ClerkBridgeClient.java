package id.gaussian.keycloak.clerk;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import org.keycloak.util.JsonSerialization;

/** Thin HTTP client for the clerk-bridge service. All Clerk logic lives in the bridge. */
public class ClerkBridgeClient {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ClerkUser(String id, String username, String email, boolean emailVerified,
                            String firstName, String lastName, boolean passwordEnabled) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Verification(boolean verified) {
    }

    /** The bridge was unreachable or answered with an unexpected status. */
    public static class BridgeException extends RuntimeException {
        BridgeException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final String baseUrl;
    private final String token;

    public ClerkBridgeClient(String baseUrl, String token) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.token = token;
    }

    /** Finds a Clerk user by username, or by email when the identifier contains "@". */
    public Optional<ClerkUser> lookup(String identifier) {
        return getUser("/users/lookup?identifier=" + encode(identifier));
    }

    public Optional<ClerkUser> get(String clerkId) {
        return getUser("/users/" + encode(clerkId));
    }

    public boolean verifyPassword(String clerkId, String password) {
        try {
            String body = JsonSerialization.writeValueAsString(Map.of("password", password));
            HttpResponse<String> res = send(request("/users/" + encode(clerkId) + "/verify-password")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)));
            if (res.statusCode() == 404) {
                return false;
            }
            return JsonSerialization.readValue(expectOk(res), Verification.class).verified();
        } catch (IOException e) {
            throw new BridgeException("could not verify password", e);
        }
    }

    private Optional<ClerkUser> getUser(String path) {
        HttpResponse<String> res = send(request(path).GET());
        if (res.statusCode() == 404) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(expectOk(res), ClerkUser.class));
        } catch (IOException e) {
            throw new BridgeException("could not read user from bridge", e);
        }
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token);
    }

    private HttpResponse<String> send(HttpRequest.Builder builder) {
        try {
            return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new BridgeException("bridge unreachable", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new BridgeException("interrupted calling bridge", e);
        }
    }

    private static String expectOk(HttpResponse<String> res) {
        if (res.statusCode() != 200) {
            throw new BridgeException("bridge answered HTTP " + res.statusCode(), null);
        }
        return res.body();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
