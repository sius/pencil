# Additional Spring Boot PasswordEncoders for Salted SHA encoded passwords
The salted secure hash algorithms used in this library do not meet today's security standards (and are deprecated or no longer supported in Spring Boot). They should therefore not be used.The library only supports developers in dealing with legacy systems (LDAP) that still manage users with insecure passsword hashes and that cannot easily be taken out of production operation.

The third-party Spring Boot starter library provides a custom DelegationPasswordEncoder Bean 
for the following PasswordEncoder encode Ids and aliases:

- bcrypt (`org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`)
- scrypt (`org.springframework.security.crypto.scrypt.SCryptPasswordEncoder`)
- pbkdf2 (`org.springframework.security.crypto.password.Pbkdf2PasswordEncoder`)
- ldap, SHA, SSHA (SSHA1, SSHA-1) (`LdapShaPasswordEncoder` compatible implementation of the legacy/non secureSalted Secure Hash Algorithm)
- SSHA224 (SSHA-224), SSHA256 (SSHA-256), SSHA384 (SSHA-384), SSHA512 (SSHA-512)

The default PasswordEncoder for encoding is `BCryptPasswordEncoder`, 
while a password matching challenge against the encoded password tries to retrieve 
a suitable PasswordEncoder identified by it's leading encode identifier, e.g.: `{SSHA512}`, `{bcrypt}` etc.
The default PasswordEncoder for encoding can be changed with the `liquer.pencil.default-encode-id` property, e.g.:
`liquer.pencil.default-encode-id: SSHA512`

## Usage

Add `pencil-spring-boot-starter` dependency and inject the provided PasswordEncoder Bean.

```xml
<dependency>
  <groupId>io.liquer.pencil</groupId>
  <artifactId>pencil-spring-boot-starter</artifactId>
  <version>2.0.2</version>
</dependency>
```

> __IMPORTANT__:  
> __Please do not use older versions than 2.0.1__:
> - Version 2.0.0 leaks password hash to stdout
> - Version < 2.0.0 fails to match long passwords due an utf-8 encoding bug
> see [Changelog](./CHANGELOG.md)

_field injection example_
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
    enabled: true # (default true)
    default-encode-id: SSHA512 # The default encode id for encoding passwords. (default: bcrypt)
    uf-safe: false # Whether to base64 encode password hashes URL and file safe. (default: false)
    no-padding: false # Whether to base64 encode password hashes without padding. (default: false)
    salt-size: 8 # The salt size in bytes. (default: 8)
```

Use custom encoding identifier {SSHA512}, {SSHA-512} ... on direct PasswordEncoder construction.
