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
 * Salted SHA-1 PasswordEncoder.
 *
 * @author sius
 */
public final class SSHAPasswordEncoder extends SaltedMessageDigestPasswordEncoder {

  /**
   * Creates a PasswordEncoder with short encoding identifier {SSHA}
   * and a random 8 byte salt value.
   * compatible with org.springframework.security.crypto.password.LdapShaPasswordEncoder
   */
  public SSHAPasswordEncoder() {
    this(SSHA_SHORT_IDENTIFIER, DEFAULT_SALT_SIZE,false, false);
  }

  /**
   * Creates a PasswordEncoder with a custom encoding identifier,
   * e.g.: {SSHA}, {SSHA1}, {SSHA-1} ...
   * @param identifier  {SSHA}, {SSHA1}, {SSHA-1} ...
   * @param saltSize  the salt byte array size (with a minimum of 8 bytes)
   */
  public SSHAPasswordEncoder(String identifier, int saltSize) {
    this(identifier, saltSize,false,false);
  }

  /**
   * Creates a PasswordEncoder with a custom encoding identifier,
   * e.g.: {SSHA}, {SSHA1}, {SSHA-1} ...
   * and base64 encoding options.
   * @param identifier  {SSHA}, {SSHA1}, {SSHA-1} ...
   * @param saltSize  the salt byte array size (with a minimum of 8 bytes)
   * @param ufSafe  url and file safe base64 encoding if true
   * @param noPadding  drop trailing base64 padding ('=') if true
   */
  public SSHAPasswordEncoder(String identifier, int saltSize, boolean ufSafe, boolean noPadding) {
    super(
        SHA1_ALGORITHM, SHA1_HASH_SIZE,
            new HashSet<>(
              Arrays.asList(
                  SSHA_SHORT_IDENTIFIER,
                  SSHA_LONG_IDENTIFIER,
                  EMPTY_IDENTIFIER
              )),
        identifier, saltSize, ufSafe, noPadding);
  }
}
