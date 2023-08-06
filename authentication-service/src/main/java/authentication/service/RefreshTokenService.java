package security.auth.service;


import security.auth.model.RefreshToken;

public interface RefreshTokenService {
    RefreshToken saveToken(String email);
    boolean validateToken(RefreshToken refreshToken);
    RefreshToken findRefreshTokenByToken(String token);
    RefreshToken findRefreshTokenByEmail(String token);
}
