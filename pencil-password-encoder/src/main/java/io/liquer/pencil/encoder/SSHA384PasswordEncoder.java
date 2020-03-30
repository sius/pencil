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
 * Salted SHA-384 PasswordEncoder.
 *
 * @author sius
 */
public final class SSHA384PasswordEncoder extends SaltedMessageDigestPasswordEncoder {

  /**
   * Creates a PasswordEncoder with short encoding identifier {SSHA384}
   * and a random 8 byte salt value.
   */
  public SSHA384PasswordEncoder() {
    this(SSHA384_SHORT_IDENTIFIER, DEFAULT_SALT_SIZE);
  }

  /**
   * Creates a PasswordEncoder with a custom encoding identifier,
   * e.g.: {SSHA384}, {SSHA-384} ...
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
   * @param ufSafe url and file safe encoding if true
   * @param noPadding drop trailing base64 padding ('=') if true
   */
  public SSHA384PasswordEncoder(String identifier, int saltSize, boolean ufSafe, boolean noPadding) {
    super(
        SHA384_ALGORITHM, SHA384_HASH_SIZE, new HashSet<>(
            Arrays.asList(
                SSHA384_SHORT_IDENTIFIER,
                SSHA384_LONG_IDENTIFIER,
                EMPTY_IDENTIFIER
            )),
        identifier, saltSize, ufSafe, noPadding);
  }
}
