package com.magadiflo.app.domain;


import javax.persistence.*;
import java.io.Serializable;
import java.util.Collection;

@Entity
@Table(name = "users")
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private boolean enabled;
    private boolean tokenExpired;

    /**
     * Por defecto, al terminar en ...Many, es del tipo LAZY.
     * Aquí, se colocó el tipo EAGER porque en la clase JpaApplicationUserDaoService, método
     * selectApplicationUserByUsername(...), una vez que se obtiene el usuario user desde la BD,
     * dentro del método se trata de acceder a sus ROLES (user.getRoles()), trayendo consigo un
     * error, puesto que la transacción ya ha finalizado. Entonces la solución que se le aplicó aquí fue
     * esa, colocarle EAGER para que cuando haga la consulta a la BD traiga también sus roles...
     * Otra solución que vi, es que si no queremos colocar el EAGER, sino dejarlo por defecto con LAZY es
     * anotar en clase con @Transactional, la clase @Service, clase donde se está llamando a los roles
     * user.getRoles() (Ver el README.md), de esa manera se obtendrán los datos de la BD DURANTE LA TRANSACCIÓN
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
    private Collection<Role> roles;

    public User() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isTokenExpired() {
        return tokenExpired;
    }

    public void setTokenExpired(boolean tokenExpired) {
        this.tokenExpired = tokenExpired;
    }

    public Collection<Role> getRoles() {
        return roles;
    }

    public void setRoles(Collection<Role> roles) {
        this.roles = roles;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("User{");
        sb.append("id=").append(id);
        sb.append(", firstName='").append(firstName).append('\'');
        sb.append(", lastName='").append(lastName).append('\'');
        sb.append(", email='").append(email).append('\'');
        sb.append(", password='").append(password).append('\'');
        sb.append(", enabled=").append(enabled);
        sb.append(", tokenExpired=").append(tokenExpired);
        sb.append('}');
        return sb.toString();
    }
}
