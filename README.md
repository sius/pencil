# Preliminary note
The salted secure hash algorithms used in this library do not meet today's security standards (
and are deprecated or no longer supported in Spring Boot).
They should therefore not be used.
The library is intended only as support for developers
who need to cope with legacy systems (LDAP) that still manage users
with insecure password hashes and that cannot be easily removed
from production use.

Before using this library, it should therefore be checked whether a password rotation procedure is possible, so that password hashes can always be generated or updated with a hash algorithm that complies with the current security standards.

## Additional Spring Boot PasswordEncoders for Salted SHA encoded passwords
The third-party Spring Boot starter library provides a custom DelegatingPasswordEncoder Bean
for the following PasswordEncoder encode Ids and aliases:

- bcrypt (`org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`)
- scrypt (`org.springframework.security.crypto.scrypt.SCryptPasswordEncoder`)
- pbkdf2 (`org.springframework.security.crypto.password.Pbkdf2PasswordEncoder`)
- XOR, ldap, SHA, SSHA (SSHA1, SSHA-1) (`LdapShaPasswordEncoder` compatible implementation of the legacy/non secureSalted Secure Hash Algorithm)
- SHA224 (SHA-224), SHA256 (SHA-256), SHA384 (SHA-384), SHA512 (SHA-512)
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
  <version>2.0.2
```

> __IMPORTANT__:  
> Please do not use older versions than 2.0.1:
> - longer passwords fail due an utf-8 encoding bug
> - Version 2.0.0 leaks password hash to stdout
> - Since Version 2.0.0 the autoconfiguration Property charset has been removed.

_field injection example_
```java

import org.springframework.beans.factory.annotation.Autowired;

@Autowired
private PasswordEncoder passwordEncoder;

```

To avoid an unintentional security leak the auto-configuration and
thus the loading of the provided `DelegatingPasswordEncoder` Bean
must be enabled by setting the environment property `liquer.pencil.enabled` to `true`.


```yaml
# application.yml

liquer.pencil.enabled: true

```

```yaml
# application.properties

liquer.pencil.enabled = true

```

## Additional `DelegatingPasswordEncoder` options via Spring boot Properties 

```yaml
liquer:
  pencil:
    enabled: false # (default false)
    default-encoding-id: SSHA512 # The default encode id for encoding passwords. (default: bcrypt)
    uf-safe: false # Whether to base64 encode password hashes URL and file safe. (default: false)
    no-padding: false # Whether to base64 encode password hashes without padding. (default: false)
    salt-size: 8 # The salt size in bytes. (default: 8)
    allow-unsalted-passwords: true (default: true)
    with-security-advice: true (default: false)
```

## Create a customized DelegatingPasswordEncoder

[CustomLegacyPasswordEncoderConfig.java](./pencil-tests/src/test/java/io/liquer/pencil/autoconfigure/CustomLegacyPasswordEncoderConfig.java)

```java
@Profile("legacy")
@Configuration
public class CustomLegacyPasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {

        final Map<String, PasswordEncoder> encoders = new HashMap<>();
        final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
        encoders.put("bcrypt", bcrypt);
        encoders.put("SHA", new SSHAPasswordEncoder(KeyGenerators.secureRandom(0)));
        encoders.put("SSHA", new SSHAPasswordEncoder());
        encoders.put("SSHA512", new SSHA512PasswordEncoder());
        encoders.put("xor", new XORPasswordEncoder().withIterations(10));

        final DelegatingPasswordEncoder ret = new DelegatingPasswordEncoder("bcrypt", encoders);
        ret.setDefaultPasswordEncoderForMatches(bcrypt);
        return ret;
    }
}
```
