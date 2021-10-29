/*
 * Copyright (c) 2021 Uwe Schumacher.
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

package io.liquer.pencil.encoder.legacy;

import io.liquer.pencil.encoder.support.Base64Support;
import io.liquer.pencil.encoder.support.EPSplit;
import io.liquer.pencil.encoder.support.EncoderSupport;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * The abstract base class for the salted MessageDigest PasswordEncoder implementations.
 *
 * @author sius
 */
abstract class SaltedMessageDigestPasswordEncoder implements PencilPasswordEncoder {

  private static Logger LOG = LoggerFactory.getLogger(SaltedMessageDigestPasswordEncoder.class);

  public static final int DEFAULT_KEY_LENGTH = 8;

  public static int MD5_HASH_SIZE = 16;
  public static String MD5_ALGORITHM = "MD5";

  public static int SHA1_HASH_SIZE = 20;
  public static String SHA1_ALGORITHM = "SHA-1";

  public static int SHA224_HASH_SIZE = 28;
  public static String SHA224_ALGORITHM = "SHA-224";

  public static int SHA256_HASH_SIZE = 32;
  public static String SHA256_ALGORITHM = "SHA-256";

  public static int SHA384_HASH_SIZE = 48;
  public static String SHA384_ALGORITHM = "SHA-384";

  public static int SHA512_HASH_SIZE = 64;
  public static String SHA512_ALGORITHM = "SHA-512";

  private final String algorithm;
  private final int hashSize;
  protected final BytesKeyGenerator saltGenerator;
  private final boolean ufSafe;
  private final boolean noPadding;

  private int iterations;
  protected String encodingId;

  protected SaltedMessageDigestPasswordEncoder(
          String algorithm, int hashSize,
          BytesKeyGenerator saltGenerator,
          int iterations,
          boolean ufSafe, boolean noPadding) {

    this.algorithm = algorithm;
    this.hashSize = hashSize;
    this.saltGenerator = (saltGenerator == null
        ? KeyGenerators.secureRandom(8)
        : saltGenerator);
    this.iterations = Math.max(1, iterations);
    this.ufSafe = ufSafe;
    this.noPadding = noPadding;
    this.encodingId = null;
  }

  /**
   * Prepend the default encodingId identifier.
   * Any brackets: {,},(,),[,] will be removed
   * This Method is for backward compatibility,
   * because some deprecated <code>PasswordEncoders</code>> prepend an encodingId identifier,
   * (e.g.: LdapShaPasswordEncoder)
   *
   * @return this <code>PasswordEncoder</code>
   */
  @Override
  public abstract PencilPasswordEncoder withEncodingId();

  /**
   * Prepend an encodingId identifier.
   * Any brackets: {,},(,),[,] will be removed
   * This Method is for backward compatibility,
   * because some deprecated <code>PasswordEncoders</code>> prepend an encodingId identifier,
   * (e.g.: LdapShaPasswordEncoder)
   *
   * @param encodingId
   * @return this <code>PasswordEncoder</code>
   */
  @Override
  public PencilPasswordEncoder withEncodingId(String encodingId) {
    this.encodingId = sanitizeEncodingId(encodingId);
    return this;
  }

  @Override
  public PencilPasswordEncoder withIterations(int iterations) {
    this.iterations = sanitizeIterations(iterations);
    return this;
  }

  /**
   * Encode the raw password and return
   * the encoded password without encodingId identifier
   * or with encodingId identifier if specified with <code>{@link #withEncodingId(String)}</code>
   *
   * @param rawPassword plain text password
   * @return b64(sha(rawPassword, salt))) or {encodingId}b64(sha(rawPassword, salt)))
   */
  @Override
  public String encode(CharSequence rawPassword) {
    if (rawPassword == null) {
      return null;
    }
    final byte [] salt = salt();
    return (EncoderSupport.isNullOrEmpty(encodingId))
        ? b64(sha(rawPassword, salt))
        : String.format("{%s}%s", encodingId, b64(sha(rawPassword, salt)));
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (rawPassword == null ||
        EncoderSupport.isNullOrEmpty(encodedPassword)) {
      return false;
    }

    final EPSplit split = new EPSplit(encodedPassword, hashSize);

    final byte[] salt = split.getSalt();
    if (split.getSaltSize() < 0) {
      return false;
    }
    final byte[] challenge = sha(rawPassword, salt);

    return MessageDigest.isEqual(split.getHashOrCipher(), challenge);
  }

  private String b64(byte[] val) {
    return Base64Support.base64Encode(val, ufSafe, noPadding);
  }

  private byte[] sha(CharSequence rawPassword, byte[] salt) {
    final MessageDigest md = md();
    if (md == null) {
      return null;
    }

    md.update(EncoderSupport.encode(rawPassword, StandardCharsets.UTF_8));
    md.update(salt);

    byte[] ret = md.digest();
    for(int i = 1; i < this.iterations; ++i) {
      ret = md.digest(ret);
    }

    return EncoderSupport.concat(ret, salt);
  }

  private byte[] salt() {
    return saltGenerator.generateKey();
  }

  private MessageDigest md() {
    try {
      return MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      LOG.error(e.getMessage(), e);
      return null;
    }
  }
}
