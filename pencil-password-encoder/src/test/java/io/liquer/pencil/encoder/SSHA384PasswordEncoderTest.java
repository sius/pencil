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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author sius
 */
public class SSHA384PasswordEncoderTest {

  @Test
  void encodeWithShortIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder = new SSHA384PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    TestHelper.log(encoded);
    assertTrue(encoded.startsWith(SSHA384PasswordEncoder.SSHA384_SHORT_IDENTIFIER));
  }

  @Test
  void encodeWithLongIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder = new SSHA384PasswordEncoder(
        SSHA384PasswordEncoder.SSHA384_LONG_IDENTIFIER,
        8 );
    final String encoded = encoder.encode(rawPassword);
    TestHelper.log(encoded);
    assertTrue(encoded.startsWith(SSHA384PasswordEncoder.SSHA384_LONG_IDENTIFIER));

  }

  @Test
  void encodeWithEmptyIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder =
        new SSHA384PasswordEncoder("", 8);
    final String encoded = encoder.encode(rawPassword);
    TestHelper.log(encoded);
    assertEquals(-1, encoded.indexOf('{'));
    assertEquals(-1, encoded.indexOf('}'));
  }

  @Test
  void challengeRawPasswordWithLongIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder = new SSHA384PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithShortIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder = new SSHA384PasswordEncoder(
        SSHA384PasswordEncoder.SSHA384_SHORT_IDENTIFIER,
        8 );
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithEmptyIdentifier1() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder =
        new SSHA384PasswordEncoder("",8);
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithEmptyIdentifier2() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder =
        new SSHA384PasswordEncoder("{}",8);
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier1() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder =
        new SSHA384PasswordEncoder("{",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier2() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder =
        new SSHA384PasswordEncoder("}",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier3() {
    final CharSequence rawPassword = "test";
    final SSHA384PasswordEncoder encoder =
        new SSHA384PasswordEncoder("{SSHA-512}",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }
}
