package com.magadiflo.app.auth;

import com.magadiflo.app.domain.Permission;
import com.magadiflo.app.domain.Role;
import com.magadiflo.app.domain.User;
import com.magadiflo.app.repository.IUserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Repository("userJpa")
public class JpaApplicationUserDaoService implements ApplicationUserDao {

    private final IUserRepository userRepository;

    public JpaApplicationUserDaoService(IUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        User user = this.userRepository.findByEmail(username);
        if (user == null) {
            throw new UsernameNotFoundException(String.format("El usuario %s no fue encontrado en la BD", username));
        } else {
            return Optional.of(new ApplicationUser(this.getAuthorities(user.getRoles()),
                    user.getPassword(), user.getEmail(),
                    true, true, true, true));
        }
    }

    private Set<? extends GrantedAuthority> getAuthorities(Collection<Role> roles) {
        return this.getGrantedAuthorities(this.getPermissions(roles));
    }

    private List<String> getPermissions(Collection<Role> roles) {
        return Stream.concat(this.getRolesNameAsPermission(roles).stream(), this.getNameOfEachPermission(roles).stream())
                .collect(Collectors.toList());
    }

    private List<String> getRolesNameAsPermission(Collection<Role> roles) {
        return roles.stream().map(Role::getName).collect(Collectors.toList());
    }

    private List<String> getNameOfEachPermission(Collection<Role> roles) {
        return roles.stream()
                .map(Role::getPermissions)
                .flatMap(Collection::stream)
                .map(Permission::getName)
                .distinct()
                .collect(Collectors.toList());
    }

    private Set<GrantedAuthority> getGrantedAuthorities(List<String> permissions) {
        return permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
    }

}
