package security.auth.payload.request;


import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor

public class VendorRegistrationRequest {
    private String firstname;
    private String lastname;
    private String phone_number;
    private String shopName;
    private String address;
}
