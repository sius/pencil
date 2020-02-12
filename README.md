# Password Encoder Auto Configuration

The auto configuration provides a custom DelegationPasswordEncoder 
for the following encoding identifiers and aliases:
- bcrypt (`org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`)
- scrypt (`org.springframework.security.crypto.scrypt.SCryptPasswordEncoder`)
- pbkdf2 (`org.springframework.security.crypto.password.Pbkdf2PasswordEncoder`)
- ldap, SSHA, SSHA1, SSHA-1 (LdapShaPasswordEncoder compatible implmentation)
- SSHA224, SSHA-224
- SSHA256, SSHA-256
- SSHA384, SSHA-384
- SHAA512, SSHA-512