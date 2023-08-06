package security.auth.model;

import jakarta.persistence.*;
import lombok.*;
import java.util.Date;

@Entity
@Table(
        name = "customer", indexes = {
        @Index(name = "customer_table_index", columnList = "email"),
        @Index(name = "idx_customer_id", columnList = "id")}
)
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class Customer {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "customer_id_sequence_generator")
    @SequenceGenerator(sequenceName = "customer_id_sequence", name = "customer_id_sequence_generator")
    private Long id;
    private String firstname;
    private String lastname;
    private String image;
    private String email;
    @OneToOne(targetEntity = User.class)
    private User user;
    private String phoneNumber;
    private Date dob;
    private String address;
    private String country;
}
