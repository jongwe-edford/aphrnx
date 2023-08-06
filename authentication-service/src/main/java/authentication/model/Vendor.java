package security.auth.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "vendor", indexes = {
        @Index(name = "vendor_table_index", columnList = "email"),
        @Index(name = "idx_vendor_id", columnList = "id")}
)
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
@ToString
public class Vendor {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "vendor_id_sequence_generator")
    @SequenceGenerator(sequenceName = "vendor_id_sequence", name = "vendor_id_sequence_generator")
    private Long id;
    private String firstname;
    private String lastname;
    private String image;
    private String email;
    private String shopName;
    private String shopBanner;
    private LocalDateTime createdAt;
    private String registrationIpAddress;
    @OneToOne
    private User user;
    private String phoneNumber;
    private String address;
    private String country;
}
