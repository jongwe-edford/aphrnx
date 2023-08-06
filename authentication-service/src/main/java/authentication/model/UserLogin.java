package security.auth.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "user_login", indexes = {
        @Index(name = "idx_user_login_id", columnList = "id")}
)
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@ToString
@Setter
public class UserLogin {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_login_id_sequence_generator")
    @SequenceGenerator(sequenceName = "user_login_id_sequence", name = "user_login_id_sequence_generator")
    private Long id;
    @OneToOne
    private User user;
    private LocalDateTime loginDate;
    private String ipAddress;
    private String country;
}
