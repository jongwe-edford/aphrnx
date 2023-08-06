package security.auth.payload.response;

public record LoginResponse(String accessToken, String refreshToken) {
}
