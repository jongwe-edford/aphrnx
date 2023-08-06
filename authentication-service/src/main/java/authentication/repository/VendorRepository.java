package security.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.auth.model.Vendor;

import java.util.Optional;

public interface VendorRepository extends JpaRepository<Vendor,Long> {
    Optional<Vendor> findVendorByEmail(String email);
    Boolean existsByEmail(String email);
    Boolean existsByPhoneNumber(String phoneNumber);

}
