package io.liquer.spring.security.encoder;

import java.util.Arrays;
import java.util.HashSet;

public final class SSHA224PasswordEncoder extends SaltedMessageDigestPasswordEncoder {

    /**
     * Creates a PasswordEncoder with short encoding identifier {SSHA224}
     * and a random 8 byte salt value.
     */
    public SSHA224PasswordEncoder() {
        this(SSHA224_SHORT_IDENTIFIER, 8);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA224}, {SSHA-224} ...
     * @param identifier {SSHA224}, {SSHA-224} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     */
    public SSHA224PasswordEncoder(String identifier, int saltSize) {
        this(identifier, saltSize, false, false);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA224}, {SSHA-224} ...
     * and base64 encoding options.
     * @param identifier {SSHA224}, {SSHA-224} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     * @param ufsSafe url and file safe encoding if true
     * @param noPadding drop trailing base64 padding ('=') if true
     */
    public SSHA224PasswordEncoder(String identifier, int saltSize, boolean ufsSafe, boolean noPadding) {
        super(
                SHA224_ALGORITHM, SHA224_HASH_SIZE, new HashSet<>(
                        Arrays.asList(
                                SSHA224_SHORT_IDENTIFIER,
                                SSHA224_LONG_IDENTIFIER,
                                EMPTY_IDENTIFIER
                        )),
                identifier, saltSize, ufsSafe, noPadding);
    }
}
