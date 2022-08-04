package com.magadiflo.app.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //Para poder usar las anotaciones @PreAuthorize(...) en los métodos de las APIS
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Atención:
     * El orden en la que definamos los .antMatchers(...) >>>>>>> SÍ IMPORTA <<<<<<<<
     * Ya que cuando se haga una petición, evaluará línea por línea los permisos o roles
     * definidos para cada patrón url, y si colocamos mal el orden podríamos hacer que
     * un usuario que no tenga permiso para hacer ACTUALIZACIONES o ELIMINACIONES, sí
     * lo termine realizando.
     */

    /**
     * ¿Cuándo usar la protección CSRF?
     * Nuestra recomendación es utilizar la protección CSRF para cualquier
     * solicitud que pueda ser procesada por un navegador por usuarios normales.
     * Si solo está creando un servicio que utilizan clientes que no son navegadores,
     * es probable que desee desactivar la protección CSRF.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //[Lista blanca] Todas las urls que coincidan con los patrones definidos, serán permitidas (no necesitan username and password)
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name()) //La url que comience con /api... solo serán permitidas a los usuarios con rol STUDENT
                .anyRequest().authenticated()
                .and()
                //.httpBasic(); //Autenticación básica (Basic Auth), si ingresamos por un navegador mostrará un alert donde se debe especificar username and password
                .formLogin(); //Autenticación basada en formularios
    }

    @Override
    @Bean
    public UserDetailsService userDetailsServiceBean() throws Exception {
        UserDetails magadifloUser = User.builder()
                .username("magadiflo")
                .password(this.passwordEncoder.encode("12345")) //Si queremos trabajar sin encriptar la contraseña (sin usar el passwordEncoder) debemos anteponer el {noop}, ejemplo: "{noop}12345"
//                .roles(ApplicationUserRole.STUDENT.name()) //Internamente spring security lo trabajará como: ROLE_STUDENT
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
                .build();

        UserDetails millaUser = User.builder()
                .username("milla")
                .password(this.passwordEncoder.encode("12345"))
//                .roles(ApplicationUserRole.ADMIN.name()) //Internamente spring security lo trabajará como: ROLE_ADMIN
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build();

        UserDetails escalanteUser = User.builder()
                .username("escalante")
                .password(this.passwordEncoder.encode("12345"))
//                .roles(ApplicationUserRole.ADMINTRAINEE.name()) //Internamente spring security lo trabajará como: ROLE_ADMINTRAINEE
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(magadifloUser, millaUser, escalanteUser);
    }
}
