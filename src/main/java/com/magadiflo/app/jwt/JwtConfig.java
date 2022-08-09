package com.magadiflo.app.jwt;

import com.google.common.net.HttpHeaders;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @Configuration, Para que Spring cree un Spring Bean en el contexto de la aplicación.
 *
 * Nota: Si no usamos @Configuration en este POJO, entonces necesitamos agregar en su reemplazo
 * el @ConfigurationPropertiesScan, esto también se debe hacer en la clase de aplicación Spring principal,
 * esto a partir de Spring Boot 2.2 Spring encuentra y registra clases @ConfigurationProperties a
 * través del escaneo de rutas de clase. El escaneo de @ConfigurationProperties debe optarse
 * explícitamente agregando la anotación @ConfigurationPropertiesScan. Por lo tanto, no tenemos
 * que anotar tales clases con @Component (y otras meta-anotaciones como @Configuration). En mi caso,
 * yo utilizaré el @Configuration
 *
 * "application.jwt", key base que está definida en el application.properties
 */

@Configuration
@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDays;

    public JwtConfig() {
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokenExpirationAfterDays() {
        return tokenExpirationAfterDays;
    }

    public void setTokenExpirationAfterDays(Integer tokenExpirationAfterDays) {
        this.tokenExpirationAfterDays = tokenExpirationAfterDays;
    }

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }
}
