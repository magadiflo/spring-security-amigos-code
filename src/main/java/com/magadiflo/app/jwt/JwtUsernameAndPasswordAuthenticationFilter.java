package com.magadiflo.app.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

/**
 * Clase que verificará las credenciales ingresadas por el usuario.
 * Spring Security lo hace por defecto, pero nosotros sobreescribiremos
 * ese comportamiento para tener nuestra propia implementación
 */

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
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
     *
     * Lo que ser hará en este método es crear un JWT TOKEN para enviárselo al cliente.
     *
     * Para especificar el payload (body o la data) del jwt, usaremos los claims, por lo que
     * claims === body (payload)
     *
     * Recordar que con la autenticación básica (Basic Auth) se enviaba en el HEADER
     * la clave "Authorization" con el valor del usuario y password en base64 anteponiendo la palabra Basic, ejemplo
     *      Key = Authorization
     *      Value = Basic bWlsbGE6MTIzNDU=
     * Cuando usamos JWT es similar, en este caso usamos el Bearer seguido del token
     *      key = Authorization
     *      value = Bearer fasdfeasdf65465.....
     *
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        String key = "securesecuresecuresecuresecuresecuresecuresecuresecuresecuresecure";
        String token = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
                .signWith(Keys.hmacShaKeyFor(key.getBytes()))
                .compact();

        response.addHeader("Authorization", "Bearer ".concat(token));
    }
}
