package com.magadiflo.app.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Se extiende de la clase abstracta OncePerRequestFilter,
 * ya que hay ocasiones en que los filtros ejecutan más de una vez
 * por cada request, entonces, para que solo se ejecute una
 * vez por cada request es que extendemos de dicha clase e
 * implementamos su método abstracto
 */

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey; //Es un @bean configurado en la clase JwtSecretKey

    public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authorizationHeader = request.getHeader(this.jwtConfig.getAuthorizationHeader());

        //Si entra al if, será rechazado pues no hay manera de validar la autenticación para la petición actual
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(this.jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.replace(this.jwtConfig.getTokenPrefix(), "");

        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(this.secretKey)
                    .build()
                    .parseClaimsJws(token);

            Claims body = claimsJws.getBody();
            String username = body.getSubject();
            List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities"); //"authorities", key que guarda la lista de "authority" en el token

            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(authority -> new SimpleGrantedAuthority(authority.get("authority"))) //"authority", key con la que se guarda cada authority dentro del token
                    .collect(Collectors.toSet());

            //Obtenemos la autenticación
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, simpleGrantedAuthorities);

            //En este punto podemos decir, que el cliente que envía el token ahora está autenticado
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException ex) {
            throw new IllegalStateException(String.format("Token %s cannot be truest", token));
        }

        //Continuamos con la cadena de filtros
        filterChain.doFilter(request, response);
    }

}
