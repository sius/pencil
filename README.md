# Additional Spring Boot PasswordEncoders for Salted SHA encoded passwords

The third-party Spring Boot starter library provides a custom DelegationPasswordEncoder Bean 
for the following PasswordEncoder encode Ids and aliases:

- bcrypt (`org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`)
- scrypt (`org.springframework.security.crypto.scrypt.SCryptPasswordEncoder`)
- pbkdf2 (`org.springframework.security.crypto.password.Pbkdf2PasswordEncoder`)
- ldap, SSHA (SSHA1, SSHA-1) (`LdapShaPasswordEncoder` compatible implementation of the Salted Secure Hash Algorithm)
- SSHA224 (SSHA-224), SSHA256 (SSHA-256), SSHA384 (SSHA-384), SSHA512 (SSHA-512)

The default PasswordEncoder for encoding is always `BCryptPasswordEncoder`, 
while a password matching challenge against the encoded password tries to retrieve 
a suitable PasswordEncoder identified by it's leading encode identifier, e.g.: `{SSHA512}`, `{bcrypt}` etc.

## Usage

Add `pencil-spring-boot-starter` dependency and inject PasswordEncoder Bean.

```xml
<dependency>
  <groupId>>io.liquer.pencil</groupId>
  <artifactId>pencil-spring-boot-starter</artifactId>
  <version>1.1.0</version>
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

## Additional `DelegatingPasswordEncoder` options via Spring boot Properties 

```yaml
liquer:
  pencil:
    enaled: true # (default true)
    default-encode-id: SSHA512 # The default encode id for encoding. (default: bcrypt)
    uf-safe: false # Whether to base64 encode URL and file safe. (default: false)
    no-padding: false # Whether to base64 encode without padding. (default: false)
    salt-size: 8 # The salt size in bytes. (default: 8)
    charset: ISO-8859-1 # Charset used to get bytes from password. (default: UTF-8)
```

Use custom encoding identifier {SSHA512}, {SSHA-512} ... on direct PasswordEncoder construction.
