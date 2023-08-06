package security.auth.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class CustomerUpdateRequest {
    private String phoneNumber;
    private String address;
}
