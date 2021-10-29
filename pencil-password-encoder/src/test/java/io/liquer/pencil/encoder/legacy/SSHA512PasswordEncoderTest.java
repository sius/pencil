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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author sius
 */
public class SSHA512PasswordEncoderTest {

  @Test
  void sanitizeIterations() {
    WithIterations sanitizer =
        new SSHA512PasswordEncoder();

    final int expected = 1;
    final int actual = sanitizer.sanitizeIterations(-100);

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void sanitizeEncodingId() {
    WithEncodingId sanitizer =
        new SSHA512PasswordEncoder();

    final String expected = "SSHA512";
    final String actual = sanitizer.sanitizeEncodingId("([SSHA512}}}");

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void without_EncodingId() {
    PasswordEncoder encoder = new SSHA512PasswordEncoder();
    final String actual = encoder.encode("test");
    Assertions.assertFalse(actual.startsWith("{SSHA512}"));

  }

  @Test
  void with_SSHA512_EncodingId() {
    PasswordEncoder encoder =
        new SSHA512PasswordEncoder().withEncodingId();
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{SSHA512}"));

  }

  @Test
  void with_SHA512_EncodingId() {
    PasswordEncoder encoder =
        new SSHA512PasswordEncoder(KeyGenerators.secureRandom(0)).withEncodingId();
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{SHA512}"));
  }

  @Test
  void with_custom_EncodingId() {
    PasswordEncoder encoder =
        new SSHA512PasswordEncoder().withEncodingId("custom");
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{custom}"));
  }

  @Test
  void matches_SomeLdapEncodedPasswordSucceeds() {
    final CharSequence rawPassword = "test";
    final String encodedPassword = "{SSHA512}9Vg3dzYj8vgMdB46KZzsdhHPbTkn8hIo5XHUWofd/Yo8gO73W3MFymVMcAQZx3D0S1fkLj2f1/FWherDLy2qvDAwMmY3YjA2";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder();
    assertTrue(encoder.matches(rawPassword, encodedPassword));
  }

  @Test
  void matches_WithEmptyPasswordSucceeds() {
    final CharSequence rawPassword = "";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void matches_WithNullFails() {
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder();
    final String encoded = encoder.encode(null);
    assertFalse(encoder.matches(null, encoded));
  }

  @Test
  void matches_WithoutSaltSucceeds() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder(KeyGenerators.secureRandom(0));
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }
}
