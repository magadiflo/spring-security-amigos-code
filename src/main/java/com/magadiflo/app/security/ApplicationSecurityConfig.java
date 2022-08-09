package com.magadiflo.app.security;

import com.magadiflo.app.auth.ApplicationUserService;
import com.magadiflo.app.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //Para poder usar las anotaciones @PreAuthorize(...) en los métodos de las APIS
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
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

    /**
     * logoutUrl
     * La URL que activa el cierre de sesión (default is "/logout").
     * Si la protección CSRF está habilitada (default), la solicitud también debe ser un POST.
     * Esto significa que, de forma predeterminada, se requiere POST "/logout" para activar un cierre de sesión.
     * Si la protección CSRF está deshabilitada, se permite cualquier método HTTP.
     * Se considera una buena práctica usar HTTP POST en cualquier acción que cambie de estado (es decir, cerrar sesión)
     * para protegerse contra ataques CSRF. Si realmente desea utilizar HTTP GET, puede utilizar
     * logoutRequestMatcher(new AntPathRequestMatcher(logoutURL, "GET"));
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) //Por que no usaremos sesiones
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //[Lista blanca] Todas las urls que coincidan con los patrones definidos, serán permitidas (no necesitan username and password)
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name()) //La url que comience con /api... solo serán permitidas a los usuarios con rol STUDENT
                .anyRequest().authenticated();
                //.and()
                //.httpBasic(); //Autenticación básica (Basic Auth), si ingresamos por un navegador mostrará un alert donde se debe especificar username and password
                //.formLogin()...; //Autenticación basada en formularios, si ingresamos por un navegador mostrará un formulario de login en la ruta /login (cerrar sesión /logout)

    }

    /**
     * Ahora ya no usaremos este método sobreescrito UserDetailsService userDetailsServiceBean() ....
     * sino usaremos el de nuestra propia implementación realizada en la clase ApplicationUserService,
     * ya que esa clase implementa el UserDetailsService
     */
    /**
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
     **/

    //---- Para usar la clase personalizada ApplicationUserService que implementa UserDetailsService
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(this.daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(this.passwordEncoder);
        provider.setUserDetailsService(this.applicationUserService);
        return provider;
    }
    //----

}
