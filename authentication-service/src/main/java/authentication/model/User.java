package security.auth.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import java.time.LocalDateTime;
import java.util.Collection;
import java.util.stream.Collectors;

@Entity
@Table(
        name = "users", indexes = {
        @Index(name = "user_table_index", columnList = "email"),
        @Index(name = "idx_user_id", columnList = "id")}
)
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@ToString
@Setter
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_id_sequence_generator")
    @SequenceGenerator(sequenceName = "user_id_sequence", name = "user_id_sequence_generator")
    private Long id;
    @Column(unique = true, nullable = false)
    private String email;
    @JsonIgnore
    private String password;
    private String country;
    @ManyToMany
    private Collection<Role> roles;
    private String registrationIp;
    private boolean isCustomer = false;
    private boolean isVendor = false;
    private boolean isSysAdmin = false;
    private boolean isSysManager = false;
    private LocalDateTime registrationDate;
    private LocalDateTime lastLoginDate;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
