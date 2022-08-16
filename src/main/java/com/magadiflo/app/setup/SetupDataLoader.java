package com.magadiflo.app.setup;

import com.magadiflo.app.domain.Permission;
import com.magadiflo.app.domain.Role;
import com.magadiflo.app.domain.User;
import com.magadiflo.app.repository.IPermissionRepository;
import com.magadiflo.app.repository.IRoleRepository;
import com.magadiflo.app.repository.IUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(SetupDataLoader.class);
    private boolean alreadySetup = false;
    private final IUserRepository userRepository;
    private final IRoleRepository roleRepository;
    private final IPermissionRepository permissionRepository;
    private final PasswordEncoder passwordEncoder;

    public SetupDataLoader(IUserRepository userRepository, IRoleRepository roleRepository,
                           IPermissionRepository permissionRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void onApplicationEvent(ContextRefreshedEvent event) {
        LOG.info("Accediendo al método onApplicationEvent(...)");
        LOG.info("Número de beans inicializados en el contenedor: {}", event.getApplicationContext().getBeanDefinitionCount());

        if (!this.alreadySetup) {
            // Creamos los permisos iniciales
            Permission readStudentPermission = this.createPermissionIfNotFound("student:read");
            Permission writeStudentPermission = this.createPermissionIfNotFound("student:write");
            Permission readCoursePermission = this.createPermissionIfNotFound("course:read");
            Permission writeCoursePermission = this.createPermissionIfNotFound("course:write");

            //Creamos los roles iniciales
            List<Permission> adminPermissions = new ArrayList<>(Arrays.asList(readStudentPermission, writeStudentPermission, readCoursePermission, writeCoursePermission));
            List<Permission> adminTraineePermissions = new ArrayList<>(Arrays.asList(readStudentPermission, readCoursePermission));
            List<Permission> studentPermissions = new ArrayList<>(Arrays.asList(readStudentPermission));

            Role adminRole = this.createRoleIfNotFound("ROLE_ADMIN", adminPermissions);
            Role adminTraineeRole = this.createRoleIfNotFound("ROLE_ADMINTRAINEE", adminTraineePermissions);
            Role studentRole = this.createRoleIfNotFound("ROLE_STUDENT", studentPermissions);

            //Creamos un usuarios iniciales
            this.createUserIfNotFound("Admin Test", "Admin Test", "admin.test@test.com", "test", new ArrayList<>(Arrays.asList(adminRole)));
            this.createUserIfNotFound("Admin Trainee test", "Admin Trainee Test", "admin.trainee.test@test.com", "test", new ArrayList<>(Arrays.asList(adminTraineeRole)));
            this.createUserIfNotFound("Student test", "Student Test", "student.test@test.com", "test", new ArrayList<>(Arrays.asList(studentRole)));
            this.createUserIfNotFound("Student and Admin Trainee test", "Student and Admin Trainee test", "student.admin.trainee.test@test.com", "test", new ArrayList<>(Arrays.asList(studentRole, adminTraineeRole)));

            this.alreadySetup = true;
        }
    }

    @Transactional
    private Permission createPermissionIfNotFound(final String name) {
        Permission permission = this.permissionRepository.findByName(name);
        if (permission == null) {
            permission = new Permission(name);
            permission = this.permissionRepository.save(permission);
        }
        return permission;
    }

    @Transactional
    private Role createRoleIfNotFound(final String name, final Collection<Permission> permissions) {
        Role role = this.roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
        }
        role.setPermissions(permissions);
        //Si el id del role tiene valor se hará un update, caso contrario se creará nuevo role
        return this.roleRepository.save(role);
    }

    @Transactional
    private User createUserIfNotFound(final String firstName, final String lastName, final String email,
                                      final String password, final Collection<Role> roles) {
        User user = this.userRepository.findByEmail(email);
        if (user == null) {
            user = new User();
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setEmail(email);
            user.setPassword(this.passwordEncoder.encode(password));
            user.setEnabled(true);
        }
        user.setRoles(roles);
        //Si el id del user tiene valor se hará un update, caso contrario se creará nuevo user
        return this.userRepository.save(user);
    }

}