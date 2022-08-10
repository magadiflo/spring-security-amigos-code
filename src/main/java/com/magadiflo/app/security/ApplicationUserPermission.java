package com.magadiflo.app.security;

//Se usarán en este proyecto Permissions como sinónimo de Authorities

/**
 * NOTA IMPORTANTE
 * ----------------
 * Al momento de generar nuestras authorities para un usuario, a parte
 * de agregar en la lista sus authorities o permisos, también le agregamos
 * su role, es decir, la lista contendrá, tanto sus authorities y su role.
 * Ejemplo de cómo se estaría mandando en el JWT:
 *  "authorities": [
 *     {"authority": "student:read"},   <----- permiso
 *     {"authority": "student:write"},  <----- permiso
 *     {"authority": "ROLE_ADMIN"},     <----- rol
 *     {"authority": "course:read"},    <----- permiso
 *     {"authority": "course:write"}    <----- permiso
 *   ],
 * Esto se puede ver en la enumeración ApplicationUserRole, en
 * el método getGrantedAuthorities().
 *
 * Ahora, el objetivo de hacer esto es que al momento de securizar los
 * end points, podemos usar tanto las autorities o roles.
 * Ejemplo usando el hasAnyRole(...):
 * *    @GetMapping
 * *    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
 * *    public List< Student > getAllStudents() {.....}
 *
 * * Ejemplo usando el hasAuthority(...):
 * *    @PostMapping
 * *    @PreAuthorize("hasAuthority('student:write')")
 * *    public void registerNewStudent(@RequestBody Student student) {
 *
 * Puede tomar las authorities para un control más detallado,
 * mientras que los roles deben aplicarse a grandes conjuntos de permisos.
 */
public enum ApplicationUserPermission {

    STUDENT_READ("student:read"),
    STUDENT_WRITE("student:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course:write");

    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return this.permission;
    }

}
