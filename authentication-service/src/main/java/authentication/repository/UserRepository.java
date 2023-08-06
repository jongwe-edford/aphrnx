package security.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import security.auth.model.User;

import java.time.LocalDateTime;
import java.util.Optional;

@Transactional
@Repository
public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findUserByEmail(String email);
    Boolean existsByEmail(String email);
    User findByEmail(String email);

    @Modifying
    @Query("UPDATE User u set u.lastLoginDate=?2 where u.email=?1")
    void updateLastLoginTime(String email, LocalDateTime time);
}
