package security.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import security.auth.model.UserLogin;

public interface UserLoginRepository extends JpaRepository<UserLogin, Long>, JpaSpecificationExecutor<UserLogin> {
}