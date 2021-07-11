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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;

/**
 * Salted SHA-256 PasswordEncoder.
 *
 * @author sius
 */
public final class SSHA256PasswordEncoder extends SaltedMessageDigestPasswordEncoder {

  /**
   * Creates a PasswordEncoder with short encoding identifier {SSHA256}
   * and a random 8 byte salt value.
   */
  public SSHA256PasswordEncoder() {
    this(SSHA256_SHORT_IDENTIFIER, DEFAULT_SALT_SIZE);
  }

  /**
   * Creates a PasswordEncoder with a custom encoding identifier,
   * e.g.: {SSHA256}, {SSHA-256} ...
   * @param identifier  {SSHA256}, {SSHA-256} ...
   * @param saltSize  the salt byte array size (with a minimum of 8 bytes)
   */
  public SSHA256PasswordEncoder(String identifier, int saltSize) {
    this(identifier, saltSize, StandardCharsets.UTF_8, false, false);
  }

  /**
   * Creates a PasswordEncoder with a custom encoding identifier,
   * e.g.: {SSHA256}, {SSHA-256} ...
   * @param identifier  {SSHA256}, {SSHA-256} ...
   * @param saltSize  the salt byte array size (with a minimum of 8 bytes)
   * @param charset  the charset used to get bytes from password String (default UTF-8)
   */
  public SSHA256PasswordEncoder(String identifier, int saltSize, Charset charset) {
    this(identifier, saltSize, charset, false, false);
  }

  /**
   * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA256}, {SSHA-256} ...
   * and base64 encoding options.
   * @param identifier  {SSHA256}, {SSHA-256} ...
   * @param saltSize  the salt byte array size (with a minimum of 8 bytes)
   * @param ufSafe  url and file safe base64 encoding if true
   * @param noPadding  drop trailing base64 padding ('=') if true
   */
  public SSHA256PasswordEncoder(String identifier, int saltSize, boolean ufSafe, boolean noPadding) {
    this(identifier, saltSize, StandardCharsets.UTF_8, ufSafe, noPadding);
  }

  /**
   * Creates a PasswordEncoder with a custom encoding identifier, e.g.: {SSHA256}, {SSHA-256} ...
   * and base64 encoding options.
   * @param identifier  {SSHA256}, {SSHA-256} ...
   * @param saltSize  the salt byte array size (with a minimum of 8 bytes)
   * @param charset   the charset used to get bytes from password String (default UTF-8)
   * @param ufSafe  url and file safe base64 encoding if true
   * @param noPadding  drop trailing base64 padding ('=') if true
   */
  public SSHA256PasswordEncoder(String identifier, int saltSize, Charset charset, boolean ufSafe, boolean noPadding) {
    super(
        SHA256_ALGORITHM, SHA256_HASH_SIZE, charset,
            new HashSet<>(
              Arrays.asList(
                  SSHA256_SHORT_IDENTIFIER,
                  SSHA256_LONG_IDENTIFIER,
                  EMPTY_IDENTIFIER
              )),
            identifier, saltSize, ufSafe, noPadding);
  }
}
