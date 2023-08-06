package security.auth.exception;

public class RefreshTokenExpiredException extends Throwable {
    public RefreshTokenExpiredException(String s) {
        super(s);
    }
}
