package com.magadiflo.app.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //[Lista blanca] Todas las urls que coincidan con los patrones definidos, serán permitidas (no necesitan username and password)
                .anyRequest().authenticated()
                .and()
                .httpBasic(); //Autenticación básica (Basic Auth), si ingresamos por un navegador mostrará un alert donde se debe especificar username and password
    }
}
