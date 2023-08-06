package security.auth.payload.response;

import java.time.LocalDateTime;
import java.util.Map;

public record Response(String message, Map<String ,Object> data,  LocalDateTime timestamp) {
}
