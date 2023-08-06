package security.auth.service;

import security.auth.exception.UserNotFoundException;
import security.auth.model.PasswordResetToken;

public interface PasswordResetTokenService {
    PasswordResetToken generateToken(String email) throws UserNotFoundException;
    Boolean validateToken(PasswordResetToken passwordResetToken);
    PasswordResetToken findPasswordResetTokenByToken(String token);
}
