package security.auth.service.impl;


import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import security.auth.exception.UserNotFoundException;
import security.auth.model.PasswordResetToken;
import security.auth.model.User;
import security.auth.repository.PasswordResetTokenRepository;
import security.auth.repository.UserRepository;
import security.auth.service.PasswordResetTokenService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@AllArgsConstructor
public class PasswordResetTokenServiceImpl implements PasswordResetTokenService {
    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Override
    public PasswordResetToken generateToken(String email) throws UserNotFoundException {
        User user = userRepository.findUserByEmail(email).orElseThrow(() -> new UserNotFoundException("No account exist"));
        return tokenRepository.save(PasswordResetToken
                .builder()
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .token(UUID.randomUUID().toString())
                .user(user)
                .build()
        );
    }

    @Override
    public Boolean validateToken(PasswordResetToken passwordResetToken) {
        return passwordResetToken.getExpiresAt().compareTo(Instant.now()) > 0;
    }

    @Override
    public PasswordResetToken findPasswordResetTokenByToken(String token) {
        return tokenRepository.findPasswordResetTokenByToken(token);
    }
}
