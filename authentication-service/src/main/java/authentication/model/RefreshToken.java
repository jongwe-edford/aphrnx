package security.auth.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;


@Entity
@Table(
        name = "refresh_token", indexes = {
        @Index(name = "refresh_token_table_index", columnList = "user_id"),
        @Index(name = "idx_refresh_token_id", columnList = "id")}
)
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
@ToString
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "refresh_token_id_sequence_generator")
    @SequenceGenerator(sequenceName = "refresh_token_id_sequence", name = "refresh_token_id_sequence_generator")
    private Long id;
    @ManyToOne
    private User user;
    private String token;
    private Instant issuedAt;
    private Instant expiresAt;
}
