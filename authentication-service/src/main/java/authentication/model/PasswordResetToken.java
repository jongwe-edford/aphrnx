package security.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.Hibernate;

import java.time.Instant;
import java.util.Objects;

@Entity
@Table(name = "password_reset_token")
@Builder
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class PasswordResetToken {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE,generator = "password_reset_token_sequence")
    @SequenceGenerator(name = "password_reset_token_sequence_generator",sequenceName = "password_reset_token_sequence")
    private Long id;
    @ManyToOne
    private User user;
    private String token;
    private Instant createdAt;
    private Instant expiresAt;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        PasswordResetToken that = (PasswordResetToken) o;
        return id != null && Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
