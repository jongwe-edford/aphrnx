package security.auth.service.impl;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import security.auth.model.RefreshToken;
import security.auth.model.User;
import security.auth.repository.RefreshTokenRepository;
import security.auth.repository.UserRepository;
import security.auth.service.RefreshTokenService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@AllArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {
    private final RefreshTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Override
    public RefreshToken saveToken(String email) {
        User user=userRepository.findUserByEmail(email).orElse(User.builder().build());
        return tokenRepository.save(RefreshToken
                .builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiresAt(Instant.now().plus(3, ChronoUnit.MINUTES))
                .issuedAt(Instant.now())
                .build()
        );
    }

    @Override
    public boolean validateToken(RefreshToken refreshToken) {
        System.out.println("Number "+refreshToken.getExpiresAt().compareTo(Instant.now()));
        return refreshToken.getExpiresAt().compareTo(Instant.now()) > 0;
    }

    @Override
    public RefreshToken findRefreshTokenByToken(String token) {
        return tokenRepository.findRefreshTokenByToken(token);
    }

    @Override
    public RefreshToken findRefreshTokenByEmail(String token) {
        return null;
    }
}
