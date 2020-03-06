package io.liquer.spring.security.encoder;

import java.util.Arrays;
import java.util.HashSet;

/**
 * @author sius
 */
public final class SSHA256PasswordEncoder extends SaltedMessageDigestPasswordEncoder {

    /**
     * Creates a PasswordEncoder with short encoding identifier {SSHA256}
     * and a random 8 byte salt value.
     */
    public SSHA256PasswordEncoder() {
        this(SSHA256_SHORT_IDENTIFIER, 8);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA256}, {SSHA-256} ...
     * @param identifier {SSHA256}, {SSHA-256} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     */
    public SSHA256PasswordEncoder(String identifier, int saltSize) {
        this(identifier, saltSize, false, false);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA256}, {SSHA-256} ...
     * and base64 encoding options.
     * @param identifier {SSHA256}, {SSHA-256} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     * @param ufsSafe url and file safe encoding if true
     * @param noPadding drop trailing base64 padding ('=') if true
     */
    public SSHA256PasswordEncoder(String identifier, int saltSize, boolean ufsSafe, boolean noPadding) {
        super(
                SHA256_ALGORITHM, SHA256_HASH_SIZE, new HashSet<>(
                        Arrays.asList(
                                SSHA256_SHORT_IDENTIFIER,
                                SSHA256_LONG_IDENTIFIER,
                                EMPTY_IDENTIFIER
                        )),
                identifier, saltSize, ufsSafe, noPadding);
    }
}
