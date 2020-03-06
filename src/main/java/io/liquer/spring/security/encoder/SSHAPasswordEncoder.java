package io.liquer.spring.security.encoder;

import java.util.Arrays;
import java.util.HashSet;

/**
 * @author sius
 */
public final class SSHAPasswordEncoder extends SaltedMessageDigestPasswordEncoder {

    /**
     * Creates a PasswordEncoder with short encoding identifier {SSHA}
     * and a random 8 byte salt value.
     * compatible with org.springframework.security.crypto.password.LdapShaPasswordEncoder
     */
    public SSHAPasswordEncoder() {
        this(SSHA_SHORT_IDENTIFIER, 8);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA}, {SSHA1}, {SSHA-1} ...
     * @param identifier {SSHA}, {SSHA1}, {SSHA-1} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     */
    public SSHAPasswordEncoder(String identifier, int saltSize) {
        this(identifier, saltSize, false, false);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA}, {SSHA1}, {SSHA-1} ...
     * and base64 encoding options.
     * @param identifier {SSHA}, {SSHA1}, {SSHA-1} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     * @param ufsSafe url and file safe encoding if true
     * @param noPadding drop trailing base64 padding ('=') if true
     */
    public SSHAPasswordEncoder(String identifier, int saltSize, boolean ufsSafe, boolean noPadding) {
        super(
                SHA1_ALGORITHM, SHA1_HASH_SIZE, new HashSet<>(
                        Arrays.asList(
                                SSHA_SHORT_IDENTIFIER,
                                SSHA_LONG_IDENTIFIER,
                                EMPTY_IDENTIFIER
                        )),
                identifier, saltSize, ufsSafe, noPadding);
    }
}
