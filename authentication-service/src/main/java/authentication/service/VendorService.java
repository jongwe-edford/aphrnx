package security.auth.service;

import com.google.zxing.WriterException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.multipart.MultipartFile;
import security.auth.exception.PhoneNumberAlreadyInUseException;
import security.auth.exception.VendorAlreadyExistsException;
import security.auth.exception.VendorNotFoundException;
import security.auth.model.Vendor;
import security.auth.payload.request.VendorRegistrationRequest;
import security.auth.payload.request.VendorUpdateRequest;
import java.awt.image.BufferedImage;
import java.io.IOException;

public interface VendorService {
    Vendor registerVendor(
            VendorRegistrationRequest vendorRegistrationRequest,
            HttpServletRequest httpServletRequest) throws VendorAlreadyExistsException, PhoneNumberAlreadyInUseException;

    Vendor retrieveVendorInfo(HttpServletRequest servletRequest) throws VendorNotFoundException;
    Vendor retrieveVendorInfo(Long id) throws VendorNotFoundException;

    Vendor updateVendorInfo(VendorUpdateRequest vendor) throws VendorNotFoundException;

    Long getVendorId(String token);

    BufferedImage generateVendorQRCode(long vendorId) throws IOException, WriterException;
    String updateProfileImage(String email,MultipartFile file);
    String updateShopBanner(String email,MultipartFile file);

}
