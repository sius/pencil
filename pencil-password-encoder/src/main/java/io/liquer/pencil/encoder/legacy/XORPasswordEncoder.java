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

import io.liquer.pencil.EncodingIds;
import io.liquer.pencil.encoder.LogSecurityAdvice;
import io.liquer.pencil.encoder.PencilPasswordEncoder;
import io.liquer.pencil.encoder.support.Base64Support;
import io.liquer.pencil.encoder.support.EPSplit;

import io.liquer.pencil.encoder.support.EncoderSupport;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * An additive XOR Cipher to support legacy environments.
 * The created cipher depends on the used Charset.
 *
 * (e.g. WebSphere, Liberty).
 */
public final class XORPasswordEncoder implements PencilPasswordEncoder {

  /**
   * WebSphere default Key: "_".
   */
  public static final String DEFAULT_UNREPEATED_KEY = "_";

  private final CharSequence unrepeatedKey;
  private final boolean ufSafe;
  private final boolean noPadding;
  private final Charset charset;

  private String encodingId;
  private int iterations;

  /**
   * Create an additive XOR Cipher PasswordEncoder
   * with the default unrepeated key "_", an UTF_8 Charset and
   * a single iteration.
   */
  public XORPasswordEncoder() {
    this(DEFAULT_UNREPEATED_KEY, StandardCharsets.UTF_8, 1, false, false);
  }

  /**
   * Create an additive XOR Cipher PasswordEncoder
   * with the specified unrepeatedKey, an UTF-8 Charset and
   * a single iteration.
   * @param unrepeatedKey the unrepeated key (default: "_")
   */
  public XORPasswordEncoder(CharSequence unrepeatedKey) {
    this(unrepeatedKey, StandardCharsets.UTF_8, 1, false, false);
  }

  /**
   * Create an additive XOR Cipher PasswordEncoder
   * with the specified charset and the default unrepeated key "_".
   *
   * @param charset
   */
  public XORPasswordEncoder(Charset charset) {

    this(DEFAULT_UNREPEATED_KEY, charset, 1, false, false);
  }

  /**
   * Create an additive XOR Cipher PasswordEncoder
   * with the specified unrepeatedKey and charset.
   *
   *
   * @param unrepeatedKey the unrepeated key (default: "_")
   * @param charset
   */
  public XORPasswordEncoder(CharSequence unrepeatedKey, Charset charset) {
    this(unrepeatedKey, charset, 1, false, false);
  }

  /**
   * Create an additive XOR Cipher PasswordEncoder
   * with the specified unrepeatedKey and base64 encoding options.
   * The created cipher depends on the used Charset.
   *
   * @param unrepeatedKey the unrepeated key (default: "_")
   * @param charset  the specified Charset (default: UTF-8)
   * @param iterations  the specified xor iterations (default: 1)
   * @param ufSafe url and file safe encoding if true
   * @param noPadding drop trailing base64 padding ('=') if true
   */
  public XORPasswordEncoder(
      CharSequence unrepeatedKey,
      Charset charset,
      int iterations,
      boolean ufSafe,
      boolean noPadding) {
    this.unrepeatedKey = unrepeatedKey == null ? DEFAULT_UNREPEATED_KEY : unrepeatedKey;
    this.charset = charset;
    this.iterations = Math.max(1, iterations);
    this.ufSafe = ufSafe;
    this.noPadding = noPadding;
  }

  /**
   * Encode the raw password and return
   * the encoded password without encodingId identifier
   * or with encodingId identifier if specified with <code>{@link #withEncodingId(String)}</code>.
   *
   * @param rawPassword plain text password
   * @return b64(xor(rawPassword, unrepeatedKey))) or
   *          {encodingId}b64(xor(rawPassword, unrepeatedKey)))
   */
  @Override
  public String encode(CharSequence rawPassword) {

    if (rawPassword == null) {
      return null;
    }
    return (EncoderSupport.isNullOrEmpty(encodingId))
        ? b64(xor(rawPassword, unrepeatedKey))
        : String.format("{%s}%s", encodingId, b64(xor(rawPassword, unrepeatedKey)));
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (rawPassword == null || encodedPassword == null) {
      return false;
    }

    final EPSplit split = new EPSplit(encodedPassword, 0);

    final byte[] challenge =  xor(rawPassword, unrepeatedKey);

    return MessageDigest.isEqual(split.getHashOrCipher(), challenge);
  }

  private String b64(byte[] val) {
    return Base64Support.base64Encode(val, ufSafe, noPadding);
  }

  private byte[] xor(CharSequence rawPassword, CharSequence repeatingKey) {
    byte[] rawPasswordBytes = EncoderSupport.encode(rawPassword, charset);
    final byte[] repeatingKeyBytes = EncoderSupport.encode(repeatingKey, charset);
    final byte[] ret = new byte[rawPasswordBytes.length];

    for (int next = 0; next < iterations; next++) {
      for (int i = 0; i < ret.length; i++) {
        ret[i] = (byte) (rawPasswordBytes[i] ^ repeatingKeyBytes[i % repeatingKeyBytes.length]);
      }
      rawPasswordBytes = ret.clone();
    }
    return ret.clone();
  }

  @Override
  public PencilPasswordEncoder withEncodingId() {
    return withEncodingId(EncodingIds.XOR);
  }

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

  @Override
  public PencilPasswordEncoder withSecurityAdvice(boolean giveAdvice, LogSecurityAdvice securityAdvice) {
    return null;
  }

  @Override
  public PencilPasswordEncoder withSecurityAdvice(boolean giveAdvice) {
    return null;
  }
}
