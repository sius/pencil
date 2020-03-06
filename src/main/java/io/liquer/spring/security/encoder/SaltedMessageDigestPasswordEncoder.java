/*
 * Copyright (c) 2020 Uwe Schumacher.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.liquer.spring.security.encoder;

import io.liquer.spring.security.support.Base64Support;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Set;

/**
 * @author sius
 */
abstract class SaltedMessageDigestPasswordEncoder implements PasswordEncoder {

    private static Logger LOG = LoggerFactory.getLogger(SaltedMessageDigestPasswordEncoder.class);

    private static class EPSplit {

        private byte[] salt = null;
        private byte[] hash = null;
        private boolean identifierSupported = false;
        private String identifier = null;

        private EPSplit(String encodedPassword, Set<String> supportedIdentifiers, int hashSize) {
            if ( encodedPassword == null || encodedPassword.isEmpty() ||
                    supportedIdentifiers == null ||  supportedIdentifiers.isEmpty()) {
                return;
            }

            final int start = encodedPassword.indexOf('{');
            final int end = encodedPassword.indexOf('}');

            if (start == 0 && end >= 1) {
                this.identifier = encodedPassword.substring(start, end+1).trim().toUpperCase();
                this.identifierSupported = supportedIdentifiers.contains(this.identifier);
            } else {
                this.identifier = "";
                this.identifierSupported = ((start + end) != -1);
            }
            if (identifierSupported) {
                final byte[] raw = Base64Support.base64Decode(encodedPassword.substring(end+1));
                final int saltSize = raw.length-hashSize;
                if (saltSize > 0) {
                    hash = new byte[hashSize];
                    salt = new byte[saltSize];
                    System.arraycopy(raw, 0, hash, 0, hashSize);
                    System.arraycopy(raw, hashSize, salt,0, saltSize);
                }
            }
        }

        public String getIdentifier() {
            return identifier;
        }

        public boolean isIdentifierSupported() {
            return identifierSupported;
        }

        public byte[] getSalt() {
            byte[] ret = null;
            if (salt != null) {
                ret = new byte[salt.length];
                System.arraycopy(salt, 0 , ret, 0, ret.length);
            }
            return ret;
        }
    }

    public static String EMPTY_IDENTIFIER = "{}";

    public static int SHA1_HASH_SIZE = 20;
    public static String SHA1_ALGORITHM = "SHA-1";
    public static String SSHA_SHORT_IDENTIFIER = "{SSHA}";
    public static String SSHA_LONG_IDENTIFIER = "{SSHA1}";

    public static int SHA224_HASH_SIZE = 28;
    public static String SHA224_ALGORITHM = "SHA-224";
    public static String SSHA224_SHORT_IDENTIFIER = "{SSHA224}";
    public static String SSHA224_LONG_IDENTIFIER = "{SSHA-224}";

    public static int SHA256_HASH_SIZE = 32;
    public static String SHA256_ALGORITHM = "SHA-256";
    public static String SSHA256_SHORT_IDENTIFIER = "{SSHA256}";
    public static String SSHA256_LONG_IDENTIFIER = "{SSHA-256}";

    public static int SHA384_HASH_SIZE = 48;
    public static String SHA384_ALGORITHM = "SHA-384";
    public static String SSHA384_SHORT_IDENTIFIER = "{SSHA384}";
    public static String SSHA384_LONG_IDENTIFIER = "{SSHA-384}";

    public static int SHA512_HASH_SIZE = 64;
    public static String SHA512_ALGORITHM = "SHA-512";
    public static String SSHA512_SHORT_IDENTIFIER = "{SSHA512}";
    public static String SSHA512_LONG_IDENTIFIER = "{SSHA-512}";

    private final String algorithm;
    private final String identifier;
    private final Set<String> supportedIdentifiers;
    private final int hashSize;
    private final int saltSize;
    private final boolean ufsSafe;
    private final boolean noPadding;

    protected SaltedMessageDigestPasswordEncoder(
        String algorithm,
        int hashSize,
        Set<String> supportedIdentifiers,
        String identifier,
        int saltSize,
        boolean ufsSafe,
        boolean noPadding) {

        this.algorithm = algorithm;
        this.identifier = identifier;
        this.supportedIdentifiers = supportedIdentifiers;
        this.hashSize = hashSize;
        this.saltSize = Math.max(saltSize, 8) ;
        this.ufsSafe = ufsSafe;
        this.noPadding = noPadding;
    }

    /**
     *
     * @param rawPassword plain text password
     * @return identifier + b64(concat(sha(rawPassword, salt), salt))
     */
    @Override
    public String encode(CharSequence rawPassword) {
        if (isNullOrEmpty(rawPassword)) {
            return null;
        }
        final byte [] salt = salt();
        return identifier + b64(concat(sha(rawPassword, salt), salt));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null && encodedPassword == null) {
            return true;
        }

        if (isNullOrEmpty(rawPassword) || isNullOrEmpty(encodedPassword)) {
            return false;
        }

        final EPSplit split = new EPSplit(encodedPassword, supportedIdentifiers, hashSize);
        if (!split.isIdentifierSupported()) {
            return false;
        }

        final byte[] salt = split.getSalt();
        final String challenge =  split.getIdentifier() + b64(concat(sha(rawPassword, salt), salt));

        return encodedPassword.equals(challenge);
    }

    private String b64(byte[] val) {
        return Base64Support.base64Encode(val, ufsSafe, noPadding);
    }

    private byte[] sha(CharSequence rawPassword, byte[] salt) {
        final MessageDigest md = md();
        if (md == null) {
            return null;
        }
        md.update(atob(rawPassword, StandardCharsets.UTF_8));
        md.update(salt);
        return md.digest();
    }

    private byte[] salt() {
        byte[] salt = new byte[saltSize];
        rnd().nextBytes(salt);
        return salt;
    }

    private MessageDigest md() {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            LOG.error(e.getMessage(), e);
            return null;
        }
    }

    private SecureRandom rnd() {
        return new SecureRandom();
    }

    private static byte[] atob(CharSequence seq, Charset charset) {
        return charset.encode(CharBuffer.wrap(seq)).array();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        final byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    private static boolean isNullOrEmpty(CharSequence s) {
        return (s==null || s.length() == 0);
    }
}
