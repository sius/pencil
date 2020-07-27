# Additional Spring Boot PasswordEncoders for Salted SHA encoded passwords

The third-party Spring Boot starter library provides a custom DelegationPasswordEncoder Bean 
for the following PasswordEncoder encode Ids and aliases:

- bcrypt (`org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`)
- scrypt (`org.springframework.security.crypto.scrypt.SCryptPasswordEncoder`)
- pbkdf2 (`org.springframework.security.crypto.password.Pbkdf2PasswordEncoder`)
- ldap, SSHA (SSHA1, SSHA-1) (`LdapShaPasswordEncoder` compatible implementation of the Salted Secure Hash Algorithm)
- SSHA224 (SSHA-224), SSHA256 (SSHA-256), SSHA384 (SSHA-384), SHAA512 (SSHA-512)

The default PasswordEncoder for encoding is always `BCryptPasswordEncoder`, 
while a password matching challenge against the encoded password tries to retrieve 
a suitable PasswordEncoder identified by it's leading encode identifier, e.g.: `{SSHA512}`, `{bcrypt}` etc.

## Usage

Add `pencil-spring-boot-starter` dependency and inject PasswordEncoder Bean.

```xml
<dependency>
  <groupId>io.liquer.spring.security</groupId>
  <artifactId>pencil-spring-boot-starter</artifactId>
  <version>1.0-SNAPSHOT</version>
</dependency>
```

```java

import org.springframework.beans.factory.annotation.Autowired;

@Autowired
private PasswordEncoder passwordEncoder;

```

The auto-configuration and thus the loading of the provided passwordEncoder Bean 
can be prevented by setting the environment property `liquer.pencil.enabled` to `false`.

```yaml
# application.yml

liquer.pencil.enabled: false

```

Add `pencil-password-encoder` to avoid auto-configuration of a passwordEncoder Bean

```xml
<dependency>
  <groupId>io.liquer.pencil</groupId>
  <artifactId>pencil-password-encoder</artifactId>
  <version>1.0.0</version>
</dependency>
```


## Additional encoding options on direct PasswordEncoder construction

- Use custom encoding identifier {SSHA512}, {SSHA-512} ...
- Encode with a random or custom salt
- Create an url and file safe base64 encoded password
- Drop trailing base64 padding ('=')
