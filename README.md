# Spring PasswordEncoders for LDAP encoded passwords

The auto configuration library provides a custom DelegationPasswordEncoder Bean 
for the following password encoder identifiers and aliases:

- bcrypt (`org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`)
- scrypt (`org.springframework.security.crypto.scrypt.SCryptPasswordEncoder`)
- pbkdf2 (`org.springframework.security.crypto.password.Pbkdf2PasswordEncoder`)
- ldap, SSHA, SSHA1, SSHA-1 (`LdapShaPasswordEncoder` compatible implementation of the Salted Secure Hash Algorithm)
- SSHA224, SSHA-224
- SSHA256, SSHA-256
- SSHA384, SSHA-384
- SHAA512, SSHA-512

The default PasswordEncoder for encoding is always `BCryptPasswordEncoder`, 
while a password matching challenge against the encoded password tries to retrieve 
a suitable PasswordEncoder identified by it's leading identifier, e.g.: `{SSHA512}`, `{bcrypt}` etc.

## Usage

Add dependency and inject PasswordEncoder Bean.

```xml
<dependency>
  <groupId>io.liquer.spring.security</groupId>
  <artifactId>pencil</artifactId>
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

## Additional encoding options on direct PasswordEncoder construction

- Encode with a custom encoding identifier {SSHA512}, {SSHA-512} ...
- Encode with a custom salt byte array size (with a minimum of 8 bytes)
- Create an url and file safe base64 password encoding
- Drop trailing base64 padding ('=')
