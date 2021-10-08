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

package io.liquer.pencil.encoder.support;

import java.util.Set;

public final class EPSplit {

  private byte[] salt = null;
  private byte[] hash = null;
  private boolean identifierSupported = false;
  private String identifier = null;
  private boolean prefixedSalt = true;

  /**
   * An internal helper to split encoded passwords into their parts
   * (identifier/encodId, hash, salt).
   * @param encodedPassword the encoded pssword
   * @param supportedIdentifiers a set with case sensitive encode identifiers
   * @param hashSize the algorithm specific hashSize
   */
  public EPSplit(
          String encodedPassword,
          Set<String> supportedIdentifiers, int hashSize) {
    this(encodedPassword, supportedIdentifiers, hashSize, false);
  }
  /**
   * An internal helper to split encoded passwords into their parts
   * (identifier/encodId, hash, salt).
   * @param encodedPassword the encoded pssword
   * @param supportedIdentifiers a set with case sensitive encode identifiers
   * @param hashSize the algorithm specific hashSize
   * @param prefixedSalt use prefixed salt if true
   */
  public EPSplit(
      String encodedPassword,
      Set<String> supportedIdentifiers, int hashSize, boolean prefixedSalt) {
    if (encodedPassword == null
        || supportedIdentifiers == null
        || supportedIdentifiers.isEmpty()) {
      return;
    }
    this.prefixedSalt = prefixedSalt;
    final int start = encodedPassword.indexOf('{');
    final int end = encodedPassword.indexOf('}');

    if (start == 0 && end >= 1) {
      this.identifier =
          encodedPassword
              .substring(start, end + 1)
              .trim();
      this.identifierSupported =
          supportedIdentifiers.contains(this.identifier);
    } else {
      this.identifier = "";
      this.identifierSupported = ((start + end) != -1);
    }
    if (identifierSupported) {
      if (encodedPassword.length() > end + 1) {
        final byte[] raw = Base64Support
            .base64Decode(encodedPassword.substring(end + 1));
        final int saltSize = raw.length - hashSize;
        if (saltSize > 0) {
          hash = new byte[hashSize];
          salt = new byte[saltSize];
          if (this.prefixedSalt) {
            System.arraycopy(raw, 0, salt, 0, saltSize);
            System.arraycopy(raw, saltSize, hash, 0, hashSize);
          } else {
            System.arraycopy(raw, 0, hash, 0, hashSize);
            System.arraycopy(raw, hashSize, salt, 0, saltSize);
          }
        }
      } else {
        hash = new byte[0];
        salt = new byte[0];
      }
    }
  }

  /**
   * Get the identifier part.
   * @return the identifier part
   */
  public String getIdentifier() {
    return identifier;
  }

  /**
   * Is identifier supported.
   * @return true if identifier  is supported
   */
  public boolean isIdentifierSupported() {
    return identifierSupported;
  }

  public boolean isPrefixedSalt() {
    return prefixedSalt;
  }

  /**
   * Get the salt part.
   * @return the salt part
   */
  public byte[] getSalt() {
    byte[] ret = null;
    if (salt != null) {
      ret = new byte[salt.length];
      System.arraycopy(salt, 0, ret, 0, ret.length);
    }
    return ret;
  }
}
