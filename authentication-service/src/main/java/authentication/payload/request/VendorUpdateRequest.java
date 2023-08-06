package security.auth.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class VendorUpdateRequest {
    private String phoneNumber;
    private String shopName;
    private String shopBanner;
    private String image;
    private String address;
}
