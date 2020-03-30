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

package io.liquer.pencil.encoder.legacy;

import static io.liquer.pencil.encoder.support.EncoderSupport.atob;
import static io.liquer.pencil.encoder.support.EncoderSupport.isNullOrEmpty;

import io.liquer.pencil.encoder.support.Base64Support;
import io.liquer.pencil.encoder.support.EPSplit;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * The additive XOR Cipher to support legacy environments
 * (e.g. WebSphere, Liberty).
 */
public final class XORPasswordEncoder implements PasswordEncoder {

  public static final String DEFAULT_IDENTIFIER = "{xor}";

  /**
   * WebSphere default Key: "_".
   */
  public static final String DEFAULT_UNREPEATED_KEY = "_";

  private final Set<String> supportedIdentifiers;

  private final String identifier;
  private final int unrepeatedKeySize;
  private final CharSequence unrepeatedKey;
  private final Charset charset;
  private final boolean ufSafe;
  private final boolean noPadding;

  /**
   * Create an additive XOR Cipher PasswordEncoder
   * with the default unrepeated key "_" and the
   * default ISO 8859-1 Charset.
   */
  public XORPasswordEncoder() {
    this(DEFAULT_UNREPEATED_KEY, StandardCharsets.ISO_8859_1);
  }

  /**
   * Create an additive XOR Cipher PasswordEncoder
   * with the specified unrepeatedKey.
   * @param unrepeatedKey the unrepeated key (default: "_")
   * @param charset custom Charset (default: ISO 8859-1)
   */
  public XORPasswordEncoder(CharSequence unrepeatedKey, Charset charset) {
    this(
        new HashSet<>(Arrays.asList(DEFAULT_IDENTIFIER)),
        DEFAULT_IDENTIFIER,
        unrepeatedKey,
        charset,
        false,
        false);
  }

  /**
   * Creates a PasswordEncoder with a custom encoding identifier,
   * e.g.: {xor} ...
   * and base64 encoding options.
   * @param supportedIdentifiers the supported match identifiers
   * @param identifier the custom identifier (default: "{xor}")
   * @param unrepeatedKey the unrepeated key (default: "_")
   * @param charset custom Charset (default: ISO 8859-1)
   * @param ufSafe url and file safe encoding if true
   * @param noPadding drop trailing base64 padding ('=') if true
   */
  public XORPasswordEncoder(
      Set<String> supportedIdentifiers,
      String identifier,
      CharSequence unrepeatedKey,
      Charset charset,
      boolean ufSafe,
      boolean noPadding) {
    this.supportedIdentifiers = supportedIdentifiers;
    this.identifier = identifier == null ? DEFAULT_IDENTIFIER : identifier;
    this.unrepeatedKey = unrepeatedKey == null ? DEFAULT_UNREPEATED_KEY : unrepeatedKey;
    this.unrepeatedKeySize = unrepeatedKey.length();
    this.charset = charset == null ? StandardCharsets.ISO_8859_1 : charset;
    this.ufSafe = ufSafe;
    this.noPadding = noPadding;
  }

  @Override
  public String encode(CharSequence rawPassword) {
    if (rawPassword == null) {
      return null;
    }
    return identifier + b64(xor(atob(rawPassword, charset), atob(unrepeatedKey, charset)));
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (rawPassword == null && encodedPassword == null) {
      return false;
    }

    if (isNullOrEmpty(encodedPassword)) {
      return false;
    }

    final EPSplit split = new EPSplit(encodedPassword, supportedIdentifiers, 0);
    if (!split.isIdentifierSupported()) {
      return false;
    }

    final String challenge =  split.getIdentifier()
        + b64(xor(atob(rawPassword, charset), atob(unrepeatedKey, charset)));
    return encodedPassword.equals(challenge);
  }

  private String b64(byte[] val) {
    return Base64Support.base64Encode(val, ufSafe, noPadding);
  }

  private static byte[] xor(byte[] rawPassword, byte[] repeatingKey) {
    byte[] ret = new byte[rawPassword.length];
    for (int i = 0; i < ret.length; i++) {
      ret[i] = (byte) (rawPassword[i] ^ repeatingKey[i % repeatingKey.length]);
    }
    return ret;
  }
}
