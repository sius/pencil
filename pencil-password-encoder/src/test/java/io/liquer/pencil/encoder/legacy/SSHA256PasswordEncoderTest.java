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

import io.liquer.pencil.encoder.TestHelper;
import io.liquer.pencil.encoder.WithEncodingId;
import io.liquer.pencil.encoder.WithIterations;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author sius
 */
public class SSHA256PasswordEncoderTest {

  @Test
  void sanitizeIterations() {
    WithIterations sanitizer =
        new SSHA256PasswordEncoder();

    final int expected = 1;
    final int actual = sanitizer.sanitizeIterations(-100);

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void sanitizeEncodingId() {
    WithEncodingId sanitizer =
        new SSHA256PasswordEncoder();

    final String expected = "SSHA256";
    final String actual = sanitizer.sanitizeEncodingId("([SSHA256}}}");

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void without_EncodingId() {
    PasswordEncoder encoder = new SSHA256PasswordEncoder();
    final String actual = encoder.encode("test");
    Assertions.assertFalse(actual.startsWith("{SSHA256}"));

  }

  @Test
  void with_SSHA256_EncodingId() {
    PasswordEncoder encoder =
        new SSHA256PasswordEncoder().withEncodingId();
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{SSHA256}"));

  }

  @Test
  void with_SHA256_EncodingId() {
    PasswordEncoder encoder =
        new SSHA256PasswordEncoder(KeyGenerators.secureRandom(0)).withEncodingId();
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{SHA256}"));
  }

  @Test
  void with_custom_EncodingId() {
    PasswordEncoder encoder =
        new SSHA256PasswordEncoder().withEncodingId("custom");
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{custom}"));
  }

  @Test
  void encode() {
    final CharSequence rawPassword = "test";
    final SSHA256PasswordEncoder encoder = new SSHA256PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    TestHelper.log(encoded);
  }

  @Test
  void matches_withEmptyPasswordSucceeds() {
    final CharSequence rawPassword = "";
    final SSHA256PasswordEncoder encoder = new SSHA256PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void matches_withNullFails() {
    final SSHA256PasswordEncoder encoder = new SSHA256PasswordEncoder();
    final String encoded = encoder.encode(null);
    assertFalse(encoder.matches(null, encoded));
  }

  @Test
  void matches_withoutSaltSucceeds() {
    final CharSequence rawPassword = "test";
    final SSHA256PasswordEncoder encoder = new SSHA256PasswordEncoder(KeyGenerators.secureRandom(0));
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }
}