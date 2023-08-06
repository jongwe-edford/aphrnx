package security.auth.exception.handler;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import security.auth.exception.*;

import java.time.LocalDateTime;

@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(AccountExistException.class)
    public ResponseEntity<ErrorMessage> accountExistException(AccountExistException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.BAD_REQUEST)
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorMessage> usernameNotFoundException(UserNotFoundException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.NOT_FOUND)
                .statusCode(HttpStatus.NOT_FOUND.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.NOT_FOUND);
    }


    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorMessage> badCredentialsException(BadCredentialsException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.UNAUTHORIZED)
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(RefreshTokenExpiredException.class)
    public ResponseEntity<ErrorMessage> refreshTokenExpired(RefreshTokenExpiredException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.EXPECTATION_FAILED)
                .statusCode(HttpStatus.EXPECTATION_FAILED.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.EXPECTATION_FAILED);
    }

    @ExceptionHandler(PasswordResetTokenExpiredException.class)
    public ResponseEntity<ErrorMessage> passwordResetTokenExpired(PasswordResetTokenExpiredException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.EXPECTATION_FAILED)
                .statusCode(HttpStatus.EXPECTATION_FAILED.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.EXPECTATION_FAILED);
    }

    @ExceptionHandler(VendorAlreadyExistsException.class)
    public ResponseEntity<ErrorMessage> vendorAlreadyExistException(VendorAlreadyExistsException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.FOUND)
                .statusCode(HttpStatus.FOUND.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.FOUND);
    }

    @ExceptionHandler(PhoneNumberAlreadyInUseException.class)
    public ResponseEntity<ErrorMessage> phoneNumberAlreadyInUseException(PhoneNumberAlreadyInUseException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.FOUND)
                .statusCode(HttpStatus.FOUND.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.FOUND);
    }

    @ExceptionHandler(VendorNotFoundException.class)
    public ResponseEntity<ErrorMessage> vendorNotFoundException(VendorNotFoundException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.NOT_FOUND)
                .statusCode(HttpStatus.NOT_FOUND.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(MissingServletRequestPartException.class)
    public ResponseEntity<ErrorMessage> missingServletRequestPartException(MissingServletRequestPartException ex) {
        return new ResponseEntity<>(ErrorMessage
                .builder()
                .status(HttpStatus.EXPECTATION_FAILED)
                .statusCode(HttpStatus.EXPECTATION_FAILED.value())
                .timestamp(LocalDateTime.now())
                .message(ex.getMessage())
                .build(), HttpStatus.EXPECTATION_FAILED);
    }

}

@Getter
@AllArgsConstructor
@Setter
@Builder
class ErrorMessage {
    private String message;
    private HttpStatus status;
    private int statusCode;
    private LocalDateTime timestamp;
}