package security.auth.model;

import jakarta.persistence.*;
import jakarta.persistence.GeneratedValue;
import lombok.*;


@Entity
@Table(
        name = "roles", indexes = {
        @Index(name = "idx_role_id", columnList = "id")}
)
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "customer_id_sequence_generator")
    @SequenceGenerator(sequenceName = "customer_id_sequence", name = "customer_id_sequence_generator")
    private Long id;
    @Enumerated(value = EnumType.STRING)
    private RoleEnum name;

    public Role(RoleEnum name) {
        this.name = name;
    }
}
