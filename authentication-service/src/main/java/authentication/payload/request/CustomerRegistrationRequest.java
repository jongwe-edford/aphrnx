package security.auth.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@AllArgsConstructor
@Data
public class CustomerRegistrationRequest {
    private String firstname;
    private String lastname;
    private String address;
    private Date dob;
    private String phoneNumber;
}
