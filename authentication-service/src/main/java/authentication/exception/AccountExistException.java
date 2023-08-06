package security.auth.exception;

public class AccountExistException extends Exception {
    public AccountExistException(String message) {
        super(message);
    }
}
