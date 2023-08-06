package security.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.auth.model.Customer;

import java.util.Optional;

public interface CustomerRepository extends JpaRepository<Customer,Long> {
    Optional<Customer> findCustomerByEmail(String email);
    Boolean existsByEmail(String email);
    Boolean existsByPhoneNumber(String phoneNumber);
}
