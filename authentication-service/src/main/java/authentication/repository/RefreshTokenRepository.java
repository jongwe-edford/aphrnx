package security.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.auth.model.RefreshToken;
import security.auth.model.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    RefreshToken findRefreshTokenByToken(String token);
    RefreshToken findRefreshTokenByUser(User user);
}