package io.liquer.spring.security.encoder;

import java.util.Arrays;
import java.util.HashSet;

/**
 * @author sius
 */
public final class SSHA512PasswordEncoder extends SaltedMessageDigestPasswordEncoder {

    /**
     * Creates a PasswordEncoder with short encoding identifier {SSHA512}
     * and a random 8 byte salt value.
     */
    public SSHA512PasswordEncoder() {
        this(SSHA512_SHORT_IDENTIFIER, 8);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA512}, {SSHA-512} ...
     * @param identifier {SSHA512}, {SSHA-512} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     */
    public SSHA512PasswordEncoder(String identifier, int saltSize) {
        this(identifier, saltSize, false, false);
    }

    /**
     * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA512}, {SSHA-512} ...
     * and base64 encoding options.
     * @param identifier {SSHA512}, {SSHA-512} ...
     * @param saltSize the salt byte array size (with a minimum of 8 bytes)
     * @param ufsSafe url and file safe encoding if true
     * @param noPadding drop trailing base64 padding ('=') if true
     */
    public SSHA512PasswordEncoder(String identifier, int saltSize, boolean ufsSafe, boolean noPadding) {
        super(
                SHA512_ALGORITHM, SHA512_HASH_SIZE, new HashSet<>(
                        Arrays.asList(
                                SSHA512_SHORT_IDENTIFIER,
                                SSHA512_LONG_IDENTIFIER,
                                EMPTY_IDENTIFIER
                        )),
                identifier, saltSize, ufsSafe, noPadding);
    }
}
