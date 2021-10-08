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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;

/**
 * Internal support class with common helper methods.
 */
public final class EncoderSupport {

  /**
   * Convert a CharSequence to a byte array
   * with charset specific code points.
   * @param seq the CharSequence
   * @param charset the Charset
   * @return the byte array representation
   */
  public static byte[] encode(CharSequence seq, Charset charset) {
    try {
      final ByteBuffer bytes = charset.newEncoder().encode(CharBuffer.wrap(seq));
      byte[] copy = new byte[bytes.limit()];
      System.arraycopy(bytes.array(), 0, copy, 0, bytes.limit());
      return copy;
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("Encoding failed", e);
    }
  }

  /**
   * Concatenate two byte arrays.
   * @param a first byte array
   * @param b second byte array
   * @return the concatenated byte array
   */
  public static byte[] concat(byte[] a, byte[] b) {
    final byte[] c = new byte[a.length + b.length];
    System.arraycopy(a, 0, c, 0, a.length);
    System.arraycopy(b, 0, c, a.length, b.length);
    return c;
  }

  /**
   * Test a CharSequence for null an empty.
   * @param s the tested CharSequence
   * @return true if null or empty string
   */
  public static boolean isNullOrEmpty(CharSequence s) {
    return (s == null || s.length() == 0);
  }

  private EncoderSupport() {}
}
