package com.magadiflo.app.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
}
