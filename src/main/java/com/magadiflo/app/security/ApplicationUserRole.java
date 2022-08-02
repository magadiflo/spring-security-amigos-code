package com.magadiflo.app.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.magadiflo.app.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {

    STUDENT(Sets.newHashSet()), //0 permisos para el estudiante (por ahora)
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)); //4 permisos para el administrador

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return this.permissions;
    }
}