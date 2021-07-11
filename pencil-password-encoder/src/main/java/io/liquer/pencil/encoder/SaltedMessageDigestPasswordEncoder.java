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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package io.liquer.pencil.encoder;

import io.liquer.pencil.encoder.support.Base64Support;
import io.liquer.pencil.encoder.support.EPSplit;
import io.liquer.pencil.encoder.support.EncoderSupport;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * The abstract base class for the salted MessageDigest PasswordEncoder implementations.
 *
 * @author sius
 */
abstract class SaltedMessageDigestPasswordEncoder implements PasswordEncoder {

  private static Logger LOG = LoggerFactory.getLogger(SaltedMessageDigestPasswordEncoder.class);

  public static final int DEFAULT_SALT_SIZE = 8;

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
  private final Charset charset;
  private final Set<String> supportedIdentifiers;
  private final int hashSize;
  private final int saltSize;
  private final boolean ufSafe;
  private final boolean noPadding;

  protected SaltedMessageDigestPasswordEncoder(
          String algorithm,
          int hashSize,
          Set<String> supportedIdentifiers,
          String identifier,
          int saltSize,
          boolean ufSafe,
          boolean noPadding) {

    this(algorithm, hashSize, StandardCharsets.UTF_8, supportedIdentifiers, identifier, saltSize, ufSafe,noPadding);
  }
  protected SaltedMessageDigestPasswordEncoder(
      String algorithm,
      int hashSize,
      Charset charset,
      Set<String> supportedIdentifiers,
      String identifier,
      int saltSize,
      boolean ufSafe,
      boolean noPadding) {

    this.algorithm = algorithm;
    this.identifier = identifier;
    this.charset = charset == null ? StandardCharsets.UTF_8 : charset;
    this.supportedIdentifiers = supportedIdentifiers;
    this.hashSize = hashSize;
    this.saltSize = Math.max(saltSize, 8);
    this.ufSafe = ufSafe;
    this.noPadding = noPadding;
  }

  /**
   * Encode the raw password.
   *
   * @param rawPassword plain text password
   * @return identifier + b64(concat(sha(rawPassword, salt), salt))
   */
  @Override
  public String encode(CharSequence rawPassword) {
    if (rawPassword == null) {
      return null;
    }
    final byte [] salt = salt();
    return identifier + b64(EncoderSupport.concat(sha(rawPassword, salt), salt));
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (rawPassword == null && encodedPassword == null) {
      return false;
    }

    if (EncoderSupport.isNullOrEmpty(encodedPassword)) {
      return false;
    }

    final EPSplit split = new EPSplit(encodedPassword, supportedIdentifiers, hashSize);
    if (!split.isIdentifierSupported()) {
      return false;
    }

    final byte[] salt = split.getSalt();
    final String challenge =  split.getIdentifier() + b64(EncoderSupport.concat(sha(rawPassword, salt), salt));

    return encodedPassword.equals(challenge);
  }

  private String b64(byte[] val) {
    return Base64Support.base64Encode(val, ufSafe, noPadding);
  }

  private byte[] sha(CharSequence rawPassword, byte[] salt) {
    final MessageDigest md = md();
    if (md == null) {
      return null;
    }
    md.update(EncoderSupport.atob(rawPassword, charset));
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
}
