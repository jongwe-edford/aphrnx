package security.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import security.auth.model.PasswordResetToken;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long>, JpaSpecificationExecutor<PasswordResetToken> {
    PasswordResetToken findPasswordResetTokenByToken(String token);
}