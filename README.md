# Password Encoder Auto Configuration

The auto configuration library provides a custom DelegationPasswordEncoder Bean 
for the following password encoder identifiers and aliases:
- bcrypt (`org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`)
- scrypt (`org.springframework.security.crypto.scrypt.SCryptPasswordEncoder`)
- pbkdf2 (`org.springframework.security.crypto.password.Pbkdf2PasswordEncoder`)
- ldap, SSHA, SSHA1, SSHA-1 (LdapShaPasswordEncoder compatible implementation)
- SSHA224, SSHA-224
- SSHA256, SSHA-256
- SSHA384, SSHA-384
- SHAA512, SSHA-512

The default PasswordEncoder for encoding is `BCryptPasswordEncoder`, 
while a password matching challenge against the encoded password tries to retrieve 
a suitable PasswordEncoder identified by it's leading identifier, e.g.: `{SSHA256}`, `{bcrypt}` etc.

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