package security.auth.service;


import jakarta.servlet.ServletRequest;
import org.springframework.http.ResponseEntity;
import security.auth.exception.*;
import security.auth.model.User;
import security.auth.payload.request.LoginRequest;
import security.auth.payload.request.NewPasswordRequest;
import security.auth.payload.request.RegistrationRequest;
import security.auth.payload.response.LoginResponse;
import security.auth.payload.response.Response;


public interface UserService {
    ResponseEntity<String> registerCustomer(RegistrationRequest registrationRequest, ServletRequest servletRequest) throws AccountExistException;

    ResponseEntity<String> registerVendor(RegistrationRequest registrationRequest, ServletRequest servletRequest) throws AccountExistException;

    ResponseEntity<String> registerSystemAdmin(RegistrationRequest registrationRequest, ServletRequest servletRequest) throws AccountExistException, AccountExistException;

    ResponseEntity<LoginResponse> login(LoginRequest loginRequest, ServletRequest servletRequest) throws InvalidPasswordException, AccountDisabledException;

    ResponseEntity<LoginResponse> refreshToken(String token) throws RefreshTokenExpiredException;

    Response forgotPassword(String email) throws UserNotFoundException;

    Response resetPassword(String token, NewPasswordRequest newPasswordRequest) throws PasswordResetTokenExpiredException;

    User getCurrentUserByToken(String token);

    Boolean validateJwtToken(String token);



}
