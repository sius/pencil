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

public final class EPSplit {

  private byte[] hash;
  private byte[] strippedHash;
  private byte[] salt;
  private int saltSize;
  private String encodingId;

  /**
   * A helper to split encoded passwords into their parts
   * (identifier with encodingId, hash, salt).
   *
   * @param encodedPassword the encoded password
   * @param hashSize the algorithm specific hashSize
   */
  public EPSplit(String encodedPassword, int hashSize) {
    encodingId = "";
    hash = new byte[0];
    strippedHash = new byte[0];
    salt = new byte[0];
    if (encodedPassword == null) {
      return;
    }
    final int start = encodedPassword.indexOf('{');
    final int end = encodedPassword.indexOf('}');
    encodingId = (start == 0 && end >= 1)
        ? encodedPassword.substring(start+1, end).trim()
        : "";

    if (encodedPassword.length() > end + 1) {
      hash = Base64Support
          .base64Decode(encodedPassword.substring(end + 1));
      saltSize = hash.length - hashSize;
      strippedHash = new byte[hashSize];
      salt = new byte[Math.max(saltSize, 0)];
      System.arraycopy(hash, 0, strippedHash, 0, hashSize);
      if (saltSize > 0) {
        System.arraycopy(hash, hashSize, salt, 0, saltSize);
      }
    }
  }

  /**
   * Get the identifier part <code>"{<encodingId>}"</code> or an empty <code>String</code>.
   *
   * @return the identifier part or an empty <code>String</code>
   */
  public String getIdentifier() {

    return (encodingId.isEmpty())
        ? ""
        : "{" + encodingId + "}";
  }

  /**
   * Get the encodingId from the identifier part or an empty <code>String</code>.
   *
   * @return the encodingId or an empty <code>String</code>
   */
  public String getEncodingId() {
    return this.encodingId;
  }

  /**
   * Get a copy of the salt part or an empty byte array.
   *
   * @return a copy of the salt part or an empty byte array
   */
  public byte[] getSalt() {
    return salt.clone();
  }

  /**
   * Get the calculated salt size.
   * A negative value indicates an invalid hash.
   *
   * @return the calculated salt size
   */
  public int getSaltSize() {
    return saltSize;
  }

  /**
   * Get a copy of the stripped hash (without salt) or an empty byte array.
   *
   * @return a copy of the stripped hash (without salt) or an empty byte array
   */
  public byte[] getStrippedHash() {
    return strippedHash.clone();
  }

  /**
   * Get a copy of the full hash (hash + salt), the Cipher or an empty byte array.
   *
   * @return a copy of the full hash (hash + salt), the Cipher or an empty byte array
   */
  public byte[] getHashOrCipher() {
    return hash.clone();
  }
}
