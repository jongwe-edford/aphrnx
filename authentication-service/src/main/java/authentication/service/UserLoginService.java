package security.auth.service;


import jakarta.servlet.ServletRequest;

public interface UserLoginService {
    void login(String email, ServletRequest httpServletRequest);
}
