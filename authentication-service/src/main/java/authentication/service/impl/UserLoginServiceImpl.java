package security.auth.service.impl;

import jakarta.servlet.ServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import security.auth.model.User;
import security.auth.model.UserLogin;
import security.auth.repository.UserLoginRepository;
import security.auth.repository.UserRepository;
import security.auth.service.UserLoginService;
import java.time.LocalDateTime;

@Service
@AllArgsConstructor
public class UserLoginServiceImpl implements UserLoginService {
    private final UserRepository userRepository;
    private final UserLoginRepository userLoginRepository;

    @Override
    public void login(String email, ServletRequest request) {
        User user = userRepository.findUserByEmail(email).orElseThrow();
        UserLogin userLogin = UserLogin
                .builder()
                .country(request.getLocale().getDisplayCountry())
                .loginDate(LocalDateTime.now())
                .ipAddress(request.getRemoteAddr())
                .user(user)
                .build();
        userLoginRepository.save(userLogin);
    }
}
