package security.auth.controller;

import com.google.zxing.WriterException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import security.auth.exception.PhoneNumberAlreadyInUseException;
import security.auth.exception.VendorAlreadyExistsException;
import security.auth.exception.VendorNotFoundException;
import security.auth.model.Vendor;
import security.auth.payload.request.VendorRegistrationRequest;
import security.auth.payload.request.VendorUpdateRequest;
import security.auth.service.VendorService;
import java.awt.image.BufferedImage;
import java.io.IOException;

@RestController
@AllArgsConstructor
@RequestMapping(path = "vendor")
public class VendorController {

    private final VendorService vendorService;

    @PostMapping("create")
    public ResponseEntity<Vendor> createVendorAccount(
            @RequestBody VendorRegistrationRequest vendorRegistrationRequest,
            HttpServletRequest httpServletRequest) throws VendorAlreadyExistsException, PhoneNumberAlreadyInUseException {
        return new ResponseEntity<>(vendorService.registerVendor(vendorRegistrationRequest, httpServletRequest), HttpStatus.CREATED);
    }

    @PatchMapping("update")
    public ResponseEntity<Vendor> updateVendorInfo(@RequestBody VendorUpdateRequest vendorRegistrationRequest) throws VendorNotFoundException {
        return new ResponseEntity<>(vendorService.updateVendorInfo(vendorRegistrationRequest), HttpStatus.OK);
    }

    @GetMapping("")
    public ResponseEntity<Vendor> retrieveVendorInfo(HttpServletRequest servletRequest) throws VendorNotFoundException {
        return new ResponseEntity<>(vendorService.retrieveVendorInfo(servletRequest), HttpStatus.OK);
    }

    @GetMapping(path = "info/{id}")
    public ResponseEntity<Vendor> retrieveVendorInfo(@PathVariable("id") Long id) throws VendorNotFoundException {
        return new ResponseEntity<>(vendorService.retrieveVendorInfo(id), HttpStatus.OK);
    }


    @GetMapping("/id")
    public ResponseEntity<Long> retrieveVendorId(@RequestHeader("Authorization") String token) throws VendorNotFoundException {
        return new ResponseEntity<>(vendorService.getVendorId(token), HttpStatus.OK);
    }

    @PostMapping("/update-profile")
    public ResponseEntity<String> updateProfilePic(@RequestParam("email") String email, @RequestBody MultipartFile file) {
        return new ResponseEntity<>(vendorService.updateProfileImage(email, file), HttpStatus.OK);
    } @PostMapping("/update-banner")
    public ResponseEntity<String> updateShopBanner(@RequestParam("email") String email, @RequestBody MultipartFile file) {
        return new ResponseEntity<>(vendorService.updateShopBanner(email, file), HttpStatus.OK);
    }

    @GetMapping(value = "/qr/{id}", produces =
            MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<BufferedImage> generateQrCode(@PathVariable("id") long id) throws VendorNotFoundException, IOException, WriterException {
        return new ResponseEntity<>(vendorService.generateVendorQRCode(id), HttpStatus.OK);
    }


}
