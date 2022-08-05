package com.magadiflo.app.auth;

import com.google.common.collect.Lists;
import com.magadiflo.app.security.ApplicationUserRole;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Esta clase estará simulando la recuperación de los datos de
 * una BD, pero que en realidad lo tenemos almacenados en un LIST
 */

/**
 * "fake", nombre que le daremos a esta clase repositorio para que Spring
 * se conecte a él automáticamente cuando tengamos más de una implementación
 * de la interfaz ApplicationUserDao.
 * En la clase ApplicationUserService, estamos haciendo uso de la interfaz
 * ApplicationUserDao, entonces para decirle a Spring que use esta clase
 * de repositorio "fake" como la implementación de esa interfaz (ya que podría haber varias clases la implementen)
 * le decimos que use la implementación que tiene
 * el nombre de "fake", para eso usamos la anotación @Qualifier("fake").
 *
 * Ahora, si solo tenemos una sola implementación, no sería necesario
 * utilizar la anotación @Qualifier, ni darle un nombre a esta clase repositorio.
 *
 * Siempre es recomendable, si se va a crear más de una implementación darle un
 * nombre al @Repository... y donde se le llame, utilizar el @Qualifier...
 *
**/
@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return this.getApplicationUsers()
                .stream()
                .filter(applicationUser -> applicationUser.getUsername().equals(username))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        this.passwordEncoder.encode("12345"),
                        "magadiflo",
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                        this.passwordEncoder.encode("12345"),
                        "milla",
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(
                        ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
                        this.passwordEncoder.encode("12345"),
                        "escalante",
                        true,
                        true,
                        true,
                        true)
        );
        return applicationUsers;
    }

}
