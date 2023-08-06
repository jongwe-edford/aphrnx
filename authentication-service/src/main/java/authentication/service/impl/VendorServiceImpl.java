package security.auth.service.impl;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.BufferedImageHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import security.auth.config.JwtUtil;
import security.auth.exception.PhoneNumberAlreadyInUseException;
import security.auth.exception.UserNotFoundException;
import security.auth.exception.VendorAlreadyExistsException;
import security.auth.exception.VendorNotFoundException;
import security.auth.model.User;
import security.auth.model.Vendor;
import security.auth.payload.request.VendorRegistrationRequest;
import security.auth.payload.request.VendorUpdateRequest;
import security.auth.repository.UserRepository;
import security.auth.repository.VendorRepository;
import security.auth.service.VendorService;
import java.awt.image.BufferedImage;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.time.LocalDateTime;

import static security.auth.util.QRCodeUtils.filePath;

@Service
@AllArgsConstructor
@Transactional
public class VendorServiceImpl implements VendorService {
    private final UserRepository userRepository;
    private final VendorRepository vendorRepository;
    private final RestTemplate restTemplate;
    private final JwtUtil jwtUtil;


    @Override
    public Vendor registerVendor(
            VendorRegistrationRequest vendorRegistrationRequest,
            HttpServletRequest httpServletRequest

    ) throws VendorAlreadyExistsException, PhoneNumberAlreadyInUseException {
        String token = httpServletRequest.getHeader("Authorization").substring(7);
        System.out.println(token);
        String email = jwtUtil.getEmailFromToken(token);
        if (vendorRepository.existsByEmail(email))
            throw new VendorAlreadyExistsException("The provided email is already in use by another account");
        if (vendorRepository.existsByPhoneNumber(vendorRegistrationRequest.getPhone_number()))
            throw new PhoneNumberAlreadyInUseException("The provided phone number is already in use by another account");
        User user = userRepository.findUserByEmail(email).orElseThrow(() -> new UserNotFoundException("No account exist"));

        //Save vendor image to db

        Vendor vendor = Vendor
                .builder()
                .address(vendorRegistrationRequest.getAddress())
                .firstname(vendorRegistrationRequest.getFirstname())
                .lastname(vendorRegistrationRequest.getLastname())
                .phoneNumber(vendorRegistrationRequest.getPhone_number())
                .country(httpServletRequest.getLocale().getDisplayCountry())
                .user(user)
                .shopName(vendorRegistrationRequest.getShopName())
                .createdAt(LocalDateTime.now())
                .registrationIpAddress(httpServletRequest.getRemoteAddr())
                .shopBanner("")
                .email(email)
                .build();
        System.out.println("VendorServiceImpl.registerVendor");
        return vendorRepository.save(vendor);

    }

    @Override
    public Vendor retrieveVendorInfo(HttpServletRequest servletRequest) {
        String token = servletRequest.getHeader("Authorization").substring(7);
        String email = jwtUtil.getEmailFromToken(token);
        System.out.println("The email is: " + email);
        return vendorRepository.findVendorByEmail(email).orElseThrow(() -> new UserNotFoundException("No such account exists"));
    }

    @Override
    public Vendor retrieveVendorInfo(Long id) throws VendorNotFoundException {
        return vendorRepository.findById(id).orElseThrow(() -> new VendorNotFoundException("No vendor found"));
    }

    @Override
    public Vendor updateVendorInfo(VendorUpdateRequest request) throws VendorNotFoundException {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Vendor vendor = vendorRepository.findVendorByEmail(userDetails.getUsername()).orElseThrow(() -> new VendorNotFoundException("No such account exists"));
        vendor.setAddress(request.getAddress());
        vendor.setImage(request.getImage());
        vendor.setPhoneNumber(request.getPhoneNumber());
        vendor.setShopName(request.getShopName());
        vendor.setShopBanner(request.getShopBanner());

        return vendorRepository.save(vendor);


    }

    @Override
    public Long getVendorId(String token) {
        System.out.println(token);
        token = token.substring(7);
        String email = jwtUtil.getEmailFromToken(token);
        Vendor vendor = vendorRepository.findVendorByEmail(email).orElseThrow(() -> new UserNotFoundException("No such account exists"));
        return vendor.getId();
    }

    @Override
    public BufferedImage generateVendorQRCode(long vendorId) throws IOException, WriterException {
        Vendor vendor = vendorRepository.findById(vendorId).orElseThrow();
        return generateQrCode(vendor.getEmail());


    }

    /**
     * @param email
     * @return
     */
    @Override
    public String updateProfileImage(String email,MultipartFile file) {
        Vendor vendor=vendorRepository.findVendorByEmail(email).orElseThrow();
        String saved = saveImageToDb(file, email);
        vendor.setImage(saved);
        vendorRepository.save(vendor);
        return "Image updated successfully";
    }

    /**
     * @param email
     * @return
     */
    @Override
    public String updateShopBanner(String email,MultipartFile file) {
        Vendor vendor=vendorRepository.findVendorByEmail(email).orElseThrow();
        String saved = saveShopBanner(file, email);
        vendor.setShopBanner(saved);
        vendorRepository.save(vendor);
        return "Image updated successfully";
    }

    private BufferedImage generateQrCode(String email) throws IOException, WriterException {
        Vendor vendor = vendorRepository.findVendorByEmail(email).orElseThrow();
        String namePath = filePath + email + ".png";
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        String url = ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/vendor/info/" + vendor.getId())
                .toUriString();
        BitMatrix bitMatrix = qrCodeWriter.encode(url, BarcodeFormat.QR_CODE, 250, 250);
        MatrixToImageConfig config = new MatrixToImageConfig(0xFF0AD002, 0xFFCDC041);
        return MatrixToImageWriter.toBufferedImage(bitMatrix, config);
//        MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);
    }

    private String saveImageToDb(MultipartFile file, String email) {
        String postUrl = "http://MEDIA-SERVICE/media/images/profile/save?email={email}";
        String getUrl = "http://MEDIA-SERVICE/media/images/profile/user?email=" + email;

        // multipart form body
        Resource imageResource = file.getResource();

        LinkedMultiValueMap<String, Object> parts = new LinkedMultiValueMap<>();
        parts.add("file", imageResource);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);

        HttpEntity<LinkedMultiValueMap<String, Object>> httpEntity = new HttpEntity<>(parts, httpHeaders);

        restTemplate.postForEntity(postUrl, httpEntity, String.class, email);
        String imageUrl = restTemplate.getForObject(getUrl, String.class);
        System.out.print("Image url:::===> %s \n" + imageUrl);

        return imageUrl;
    }
    private String saveShopBanner(MultipartFile file, String email) {
        String postUrl = "http://MEDIA-SERVICE/media/images/shop-banner/create/{email}";
        String getUrl = "http://MEDIA-SERVICE/media/images/shop-banner/shop/" + email;

        // multipart form body
        Resource imageResource = file.getResource();

        LinkedMultiValueMap<String, Object> parts = new LinkedMultiValueMap<>();
        parts.add("file", imageResource);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);

        HttpEntity<LinkedMultiValueMap<String, Object>> httpEntity = new HttpEntity<>(parts, httpHeaders);

        restTemplate.postForEntity(postUrl, httpEntity, String.class, email);
        String imageUrl = restTemplate.getForObject(getUrl, String.class);
        System.out.print("Image url:::===> %s \n" + imageUrl);

        return imageUrl;
    }

    @Bean
    public HttpMessageConverter<BufferedImage>
    createImageHttpMessageConverter() {
        return new BufferedImageHttpMessageConverter();
    }

}
