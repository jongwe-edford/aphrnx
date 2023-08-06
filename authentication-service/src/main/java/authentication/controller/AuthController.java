package security.auth.controller;


import jakarta.servlet.ServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import security.auth.exception.*;
import security.auth.model.User;
import security.auth.payload.request.LoginRequest;
import security.auth.payload.request.NewPasswordRequest;
import security.auth.payload.request.RegistrationRequest;
import security.auth.payload.response.LoginResponse;
import security.auth.payload.response.Response;
import security.auth.service.UserService;


@RestController
@RequestMapping(path = "auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;

    @PostMapping(path = "login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest, ServletRequest servletRequest) throws InvalidPasswordException, AccountDisabledException {
        return userService.login(loginRequest, servletRequest);
    }

    @PostMapping(path = "register/customer")
    public ResponseEntity<String> registerCustomer(@RequestBody RegistrationRequest loginRequest, ServletRequest servletRequest) throws AccountExistException {
        return userService.registerCustomer(loginRequest, servletRequest);
    }

    @PostMapping(path = "register/vendor")
    public ResponseEntity<String> registerVendor(@RequestBody RegistrationRequest loginRequest, ServletRequest servletRequest) throws AccountExistException {
        return userService.registerVendor(loginRequest, servletRequest);
    }

    @PostMapping(path = "register/sys-admin")
    public ResponseEntity<String> registerSystemAdmin(@RequestBody RegistrationRequest loginRequest, ServletRequest servletRequest) throws AccountExistException {
        return userService.registerSystemAdmin(loginRequest, servletRequest);
    }

    @PostMapping(path = "refresh")
    public ResponseEntity<LoginResponse> refreshAuthToken(@RequestParam("token") String token) throws RefreshTokenExpiredException {
        return userService.refreshToken(token);
    }

    @PostMapping(path = "forgot")
    public ResponseEntity<Response> forgotPassword(@RequestParam("email") String email) {
        return new ResponseEntity<>(userService.forgotPassword(email), HttpStatus.OK);
    }

    @PostMapping(path = "reset-password")
    public ResponseEntity<Response> resetPassword(@RequestParam("token") String token, @RequestBody NewPasswordRequest newPasswordRequest) throws PasswordResetTokenExpiredException {
        return new ResponseEntity<>(userService.resetPassword(token, newPasswordRequest), HttpStatus.OK);
    }

    @GetMapping(path = "current-user")
    public ResponseEntity<User> getCurrentUser(@RequestParam("token") String token) {
        return new ResponseEntity<>(userService.getCurrentUserByToken(token), HttpStatus.OK);
    }

    @GetMapping(path = "validate-token")
    public ResponseEntity<Boolean> validateToken(@RequestParam("token") String token) {
        return new ResponseEntity<>(userService.validateJwtToken(token), HttpStatus.OK);
    }
}
