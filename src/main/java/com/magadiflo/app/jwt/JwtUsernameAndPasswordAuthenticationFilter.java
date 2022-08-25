package com.magadiflo.app.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

/**
 * Clase que verificará las credenciales ingresadas por el usuario.
 * Spring Security lo hace por defecto usando esta clase: UsernamePasswordAuthenticationFilter,
 * pero nosotros la extendemos (JwtUsernameAndPasswordAuthenticationFilter) para sobreescribir
 * el comportamiento de los métodos: attemptAuthentication(...), successfulAuthentication(...) y
 * de esa forma tener nuestra propia implementación.
 * <p>
 * Recordar:
 * Si ingresamos a la clase que heredamos UsernamePasswordAuthenticationFilter,
 * veremos que la petición que se debe hacer tiene que venir con el método POST y a la url /login
 * y además, como parámetros debe traer los campos username y password.
 */

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    //Se observa en el ApplicationSecurityConfig, método configure(HttpSecurity http)
    //que se le pasa por el constructor de la instancia el authenticationManager(), jwtConfig y el secretKey
    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey; //Es un @bean configurado en la clase JwtSecretKey

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                      JwtConfig jwtConfig, SecretKey secretKey) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    //Sobreescribimos este método para implementar nuestra propia verificación de credenciales
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            //Aquí el AuthenticationManager se asegurará de que el usuario existe
            //y si existe, que su contraseña sea correcta
            Authentication authenticate = this.authenticationManager.authenticate(authentication);
            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * successfulAuthentication(...), método que será invocado después de que el método attemptAuthentication(...)
     * devuelva una autenticación exitosa. Si la autenticación no es exitosa, entonces este método successfulAuthentication(...)
     * jamás será ejecutado.
     * <p>
     * Lo que ser hará en este método es crear un JWT TOKEN para enviárselo al cliente.
     * <p>
     * Para especificar el payload (body o la data) del jwt, usaremos los claims, por lo que
     * claims === body (payload)
     * <p>
     * Recordar que con la autenticación básica (Basic Auth) se enviaba en el HEADER
     * la clave "Authorization" con el valor del usuario y password en base64 anteponiendo la palabra Basic, ejemplo
     * Key = Authorization
     * Value = Basic bWlsbGE6MTIzNDU=
     * Cuando usamos JWT es similar, en este caso usamos el Bearer seguido del token
     * key = Authorization
     * value = Bearer fasdfeasdf65465.....
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        String token = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(this.jwtConfig.getTokenExpirationAfterDays())))
                .signWith(this.secretKey)
                .compact();

        response.addHeader(this.jwtConfig.getAuthorizationHeader(), this.jwtConfig.getTokenPrefix().concat(token));
    }
}
