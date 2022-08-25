## Spring Security - Full Course

Taken from: https://www.youtube.com/watch?v=her_7pa0vrg&t=4406s   
**Youtube Channel:** Amigoscode

## Librería JWT usada en el proyecto
[jwtk / jjwt](https://github.com/jwtk/jjwt)

## Diferencia entre Role y Authority en Spring Security
### Tomada del siguiente [enlace](https://ajaxhispano.com/ask/diferencia-entre-el-rol-y-la-autoridad-otorgada-en-la-seguridad-de-primavera-5561/) como respuesta a la misma pregunta
`Author: James, 2017-01-02 10:30:54`

Piense en una autoridad otorgada como un "permiso" o un "derecho". Esos "permisos" se expresan (normalmente) 
como cadenas (con el método getAuthority()). Esas cadenas le permiten identificar los permisos y permitir que sus 
votantes decidan si otorgan acceso a algo.

Puede otorgar diferentes GrantedAuthoritys (permisos) a los usuarios poniéndolos en el contexto de seguridad. 
Normalmente lo hace implementando su propio UserDetailsService que devuelve una implementación de UserDetails 
que devuelve las autoridades concedidas necesarias.

Los roles (como se usan en muchos ejemplos) son solo "permisos" con una convención de nomenclatura que dice 
que un rol es una autoridad otorgada que comienza con el prefijo ROLE_. No hay nada más. Un rol es solo una 
autoridad otorgada - un "permiso" - un "derecho". 

Usted ve muchos lugares en spring security donde el rol con 
su prefijo ROLE_ es manejado especialmente como por ejemplo en RoleVoter, donde el prefijo ROLE_ es usado por defecto.

Esto le permite proporcione los nombres de los roles sin el prefijo ROLE_. 

Antes de Spring security 4, este manejo especial de "roles" no se ha seguido de manera muy consistente y las autoridades y los roles a menudo 
se trataban de la misma manera (como puede ver, por ejemplo, en la implementación del método hasAuthority() 
en SecurityExpressionRoot, que simplemente llama a hasRole()). 

Con Spring Security 4, el tratamiento de roles es más consistente y el código que trata 
con "roles" (como la expresión RoleVoter, la expresión hasRole, etc.).) 
siempre añade el ROLE_ prefijo para usted. Así que hasAuthority('ROLE_ADMIN') significa lo mismo que hasRole('ADMIN') 
porque el prefijo ROLE_ se agrega automáticamente. Consulte la guía de migración spring security 3 to 4 para obtener más información.

Pero aun así: un rol es solo una autoridad con un prefijo especial ROLE_.

Así que en Spring security 3 @PreAuthorize("hasRole('ROLE_XYZ')") es lo mismo que @PreAuthorize("hasAuthority('ROLE_XYZ')") 
y en Spring security 4 @PreAuthorize("hasRole('XYZ')") es lo mismo que @PreAuthorize("hasAuthority('ROLE_XYZ')").

Con respecto a su caso de uso:

Los usuarios tienen roles y los roles pueden realizar ciertas operaciones.

Podría terminar en GrantedAuthorities para los roles a los que pertenece un usuario y las operaciones que un rol puede realizar. 
El GrantedAuthorities para los roles tiene el prefijo ROLE_ y las operaciones tienen el prefijo OP_. 

Un ejemplo para las autoridades de operación podría ser OP_DELETE_ACCOUNT, OP_CREATE_USER, OP_RUN_BATCH_JOB, etc. 
Los roles pueden ser ROLE_ADMIN, ROLE_USER, etc.

Podrías terminar haciendo que tus entidades implementen GrantedAuthority como en este ejemplo (pseudo-código):

```
@Entity
class Role implements GrantedAuthority {

    @Id
    private String id;

    @OneToMany
    private final List<Operation> allowedOperations = new ArrayList<>();

    @Override
    public String getAuthority() {
        return id;
    }

    public Collection<GrantedAuthority> getAllowedOperations() {
        return allowedOperations;
    }
}

@Entity
class User {

    @Id
    private String id;

    @OneToMany
    private final List<Role> roles = new ArrayList<>();

    public Collection<Role> getRoles() {
        return roles;
    }
}

@Entity
class Operation implements GrantedAuthority {
    @Id
    private String id;

    @Override
    public String getAuthority() {
        return id;
    }
}
```

Los id de los roles y operaciones que crear en su base de datos sería la representación de GrantedAuthority, 
por ejemplo, "ROLE_ADMIN", "OP_DELETE_ACCOUNT", etc. Cuando se autentica un usuario, asegúrese de que todas 
las autoridades otorgadas de todos sus roles y las operaciones correspondientes se devuelven desde 
los detalles del usuario. Método getAuthorities ().

Ejemplo: 
```
El rol de administrador con id ROLE_ADMIN tiene asignadas las operaciones 
OP_DELETE_ACCOUNT, OP_READ_ACCOUNT, OP_RUN_BATCH_JOB. 
```
```
El rol de usuario con id ROLE_USER tiene la operación OP_READ_ACCOUNT.
```
Si un **administrador** inicia sesión en el contexto de seguridad resultante tendrá las **autoridades** otorgadas: 
```
ROLE_ADMIN, OP_DELETE_ACCOUNT, OP_READ_ACCOUNT, OP_RUN_BATCH_JOB
```
Si un **usuario** lo registra, tendrá: 
```
ROLE_USER, OP_READ_ACCOUNT
```
El UserDetailsService se encargaría de recopilar todos los roles y todas las 
operaciones de esos roles y hacerlos disponibles mediante el método getAuthorities() 
en la instancia UserDetails devuelta.

## [Spring Security Annotations With Examples](https://javatechonline.com/spring-security-annotations/?fbclid=IwAR2G1G3rM31azpaxSgmDlnFz1kAxEkfHe9nWwQ18ftf7riNJ40-gh2tVBUI)
Se muestra el artículo con las anotaciones usadas en Spring Security

## [What is SecurityContext and SecurityContextHolder in Spring Security?](https://javarevisited.blogspot.com/2018/02/what-is-securitycontext-and-SecurityContextHolder-Spring-security.html?fbclid=IwAR3NNeHQT1wk5PaG4nAjt2wsRC5iXJmcCjZ88d4NRe3O7w5q9QkiJ7QrmBo#ixzz6aGyiRSLO)
**Tomado de la web Javarevisited**

SecurityContext y SecurityContextHolder son dos clases fundamentales de Spring Security. 
SecurityContext se utiliza para almacenar los detalles del usuario autenticado actualmente, 
también conocido como Principal. Por lo tanto, si tiene que obtener el nombre de usuario o cualquier 
otro detalle del usuario, primero debe obtener este SecurityContext. SecurityContextHolder es una clase 
auxiliar que proporciona acceso al contexto de seguridad. De forma predeterminada, utiliza 
un objeto ThreadLocal para almacenar el contexto de seguridad, lo que significa que el contexto 
de seguridad siempre está disponible para métodos en el mismo subproceso de ejecución, 
incluso si no pasa el objeto SecurityContext. Sin embargo, no se preocupe por la 
pérdida de memoria de ThreadLocal en la aplicación web, Spring Security se encarga de limpiar ThreadLocal.  

### Cómo obtener el nombre de usuario que ha iniciado sesión actualmente en Spring Security 
Este es el código para obtener el contexto de seguridad en la seguridad de Spring y obtener 
el nombre del usuario que ha iniciado sesión actualmente:
```
Object principal = SecurityContextHolder.getContext()
                                        .getAuthentication()
                                        .getPrincipal();

if (principal instanceof UserDetails) {
    String username = ((UserDetails)principal).getUsername();
} else {
    String username = principal.toString();
}
```
[Para más información... leer más...](https://javarevisited.blogspot.com/2018/02/what-is-securitycontext-and-SecurityContextHolder-Spring-security.html#ixzz7d01N1ln2)

## Timestamps
00:00 INTRO   
01:48 QUICK WORD BEFORE WE BEGIN   
02:33 BOOTSTRAPPING   
05:47 RUNNING APP WITH INTELLIJ   
10:19 - LETS BUILD AN API   
17:12 - INSTALLING SPRING SECURITY   
20:16 - FORM BASED AUTHENTICATION OVERVIEW   
25:28 - BASIC AUTH OVERVIEW   
28:39 - BASIC AUTH   
34:12 - POSTMAN   
38:06 - ANT MATCHERS   
42:37 - APPLICATION USERS   
45:51 - IN MEMORY USER DETAILS MANAGER   
50:39 - PASSWORD ENCODING WITH BCRYPT   
56:05 - ROLES AND PERMISSIONS   
59:05 - ADMIN USER   
1:01:51 - ROLES & PERMISSIONS USING ENUMS   
1:10:08 - ROLE BASED AUTHENTICATION   
1:16:22 - PERMISSION BASED AUTHENTICATION
1:19:17 - MANAGEMENT API
1:25:58 - DISABLING CSRF   
1:32:54 - hasAuthority()   
1:36:49 - ADDING AUTHORITIES TO USERS   
1:45:22 - PERMISSION BASED AUTHENTICATION IN ACTION   
1:48:37 - ORDER DOES MATTER   
1:51:11 - preAuthorize()   
1:56:57 - UNDERSTANDING CSRF   
2:03:30 - CSRF TOKEN   
2:08:10 - HOW CSRF TOKEN GENERATION WORKS   
2:12:29 - LETS DISABLE CSRF AGAIN   
2:14:10 - FORM BASED AUTHENTICATION   
2:17:15 - ENABLE FORM BASED AUTHENTICATION   
2:20:39 - SESSION ID   
2:24:20 - CUSTOM LOGIN PAGE   
2:32:30 - REDIRECT AFTER SUCCESS LOGIN   
2:35:04 - REMEMBER ME   
2:40:00 - REMEMBER ME COOKIE AND EXTRA OPTIONS   
2:45:20 - LOGOUT   
2:53:41 - LOGOUT BUTTON   
2:58:00 - PASSWORD, USERNAME, REMEMBER-ME  PARAMETERS   
3:00:29 - DB AUTHENTICATION OVERVIEW   
3:09:00 - APPLICATION USER CLASS   
3:09:17 - APPLICATION USER SERVICE   
3:10:21 - APPLICATION USER CLASS   
3:11:43 - APPLICATION USER DAO INTERFACE   
3:15:00 - FAKE APPLICATION USER SERVICE   
3:25:19 - DAO AUTHENTICATION PROVIDER   
3:29:37 - DB AUTHENTICATION IN ACTION
3:33:54 - HELLO   
3:35:24 - INTRO TO JSON WEB TOKEN (JWT)   
3:42:30 - JWT LIBRARY   
3:46:16 -  JwtUsernameAndPasswordAuthenticationFilter - attemptAuthentication()   
3:54:34 - JwtUsernameAndPasswordAuthenticationFilter - successfulAuthentication   
4:01:45 - REQUEST FILTERS   
4:04:06 - FILTERS AND STATELESS SESSIONS   
4:08:02 - JWT USERNAME AND PASSWORD FILTER   
4:14:36 - JWT TOKEN VERIFIER FILTER   
4:29:49 - JWT TOKEN VERIFIER FILTER IN ACTION   
4:39:10 - JWT CONFIG   
4:49:24 - JWT CONFIG IN ACTION   
4:55:00 - QUICK WORD ABOUT JWT   