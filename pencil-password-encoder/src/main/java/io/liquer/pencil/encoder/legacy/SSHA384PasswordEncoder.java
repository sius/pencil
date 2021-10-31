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

import io.liquer.pencil.encoder.EncodingIds;
import io.liquer.pencil.encoder.PencilPasswordEncoder;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

/**
 * Salted or unsalted SHA-384 PasswordEncoder supporting
 * multiple digest iterations and base64 options.
 *
 * @author sius
 */
public final class SSHA384PasswordEncoder extends SaltedMessageDigestPasswordEncoder {

  /**
   * Creates a PasswordEncoder using SHA-256 algorithm,
   * a random 8 byte salt value and a single digest iteration.
   */
  public SSHA384PasswordEncoder() {
    this(KeyGenerators.secureRandom(DEFAULT_KEY_LENGTH), 1, false, false);
  }

  /**
   * Creates a PasswordEncoder using salted or unsalted SHA-384 algorithm
   * and a single digest iteration.
   *
   * @param saltGenerator  a custom salt byte array generator
   */
  public SSHA384PasswordEncoder(BytesKeyGenerator saltGenerator) {
    this(saltGenerator, 1, false, false);
  }

  /**
   * Creates a PasswordEncoder using salted or unsalted SHA-384 algorithm,
   * base64 encoding options and specified digest iterations.
   *
   * @param saltGenerator  a custom salt byte array generator
   * @param iterations  the digest iterations
   * @param ufSafe  url and file safe base64 encoding if true
   * @param noPadding  drop trailing base64 padding ('=') if true
   */
  public SSHA384PasswordEncoder(BytesKeyGenerator saltGenerator, int iterations, boolean ufSafe, boolean noPadding) {
    super(SHA384_ALGORITHM, SHA384_HASH_SIZE, saltGenerator, iterations, ufSafe, noPadding);
  }

  @Override
  public PencilPasswordEncoder withEncodingId() {
    return withEncodingId(
        (saltGenerator.getKeyLength() == 0
            ? EncodingIds.SHA384
            : EncodingIds.SSHA384));
  }
}
