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

import java.util.Arrays;
import java.util.HashSet;

/**
 * Salted SHA-512 PasswordEncoder.
 *
 * @author sius
 */
public final class SSHA512PasswordEncoder extends SaltedMessageDigestPasswordEncoder {

  /**
   * Creates a PasswordEncoder with short encoding identifier {SSHA512}
   * and a random 8 byte salt value.
   */
  public SSHA512PasswordEncoder() {
    this(SSHA512_SHORT_IDENTIFIER, DEFAULT_SALT_SIZE);
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
