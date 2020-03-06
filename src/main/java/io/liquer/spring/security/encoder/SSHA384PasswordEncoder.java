package io.liquer.spring.security.encoder;

import java.util.Arrays;
import java.util.HashSet;

/**
 * @author sius
 */
public final class SSHA384PasswordEncoder extends SaltedMessageDigestPasswordEncoder {

    /**
     * Creates a PasswordEncoder with short encoding identifier {SSHA384}
     * and a random 8 byte salt value.
     */
    public SSHA384PasswordEncoder() {
        this(SSHA384_SHORT_IDENTIFIER, 8);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA384}, {SSHA-384} ...
     * @param identifier {SSHA384}, {SSHA-384} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     */
    public SSHA384PasswordEncoder(String identifier, int saltSize) {
        this(identifier, saltSize, false, false);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA384}, {SSHA-384} ...
     * and base64 encoding options.
     * @param identifier {SSHA384}, {SSHA-384} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     * @param ufsSafe url and file safe encoding if true
     * @param noPadding drop trailing base64 padding ('=') if true
     */
    public SSHA384PasswordEncoder(String identifier, int saltSize, boolean ufsSafe, boolean noPadding) {
        super(
                SHA384_ALGORITHM, SHA384_HASH_SIZE, new HashSet<>(
                        Arrays.asList(
                                SSHA384_SHORT_IDENTIFIER,
                                SSHA384_LONG_IDENTIFIER,
                                EMPTY_IDENTIFIER
                        )),
                identifier, saltSize, ufsSafe, noPadding);
    }
}
