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
import org.springframework.security.crypto.password.PasswordEncoder;

import static io.liquer.pencil.encoder.TestHelper.log;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author sius
 */
public class SSHA512PasswordEncoderTest {

  @Test
  void encodeWithPrefixedSalt() {
    final String passwordHash = "{SSHA512}/I5AfKcK9Nl0sMXDVF8pM8KkmZRrvUEwnI4oUAI1EKikMbgzw+ykujnOgeza3FGuYtBq32XZJ306DPQHR5avuTAwOGRiMGVi";
    final CharSequence rawPassword = "Xx3vuFMXVGSQS413";
    final PasswordEncoder encoder = new SSHA512PasswordEncoder();
    final boolean actual = encoder.matches(rawPassword, passwordHash);
    assertTrue(actual);
  }

  @Test
  void encodeWithShortIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertTrue(encoded.startsWith(SSHA512PasswordEncoder.SSHA512_SHORT_IDENTIFIER));
  }

  @Test
  void encodeWithLongIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder(
        SSHA512PasswordEncoder.SSHA512_LONG_IDENTIFIER,
        8 );
    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertTrue(encoded.startsWith(SSHA512PasswordEncoder.SSHA512_LONG_IDENTIFIER));

  }

  @Test
  void encodeWithEmptyIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder =
        new SSHA512PasswordEncoder("", 8);
    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertEquals(-1, encoded.indexOf('{'));
    assertEquals(-1, encoded.indexOf('}'));
  }

  @Test
  void challengeRawPasswordWithLongIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithShortIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder(
        SSHA512PasswordEncoder.SSHA512_SHORT_IDENTIFIER,
        8 );
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithEmptyIdentifier1() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder =
        new SSHA512PasswordEncoder("",8);
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithEmptyIdentifier2() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder =
        new SSHA512PasswordEncoder("{}",8);
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier1() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder =
        new SSHA512PasswordEncoder("{",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier2() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder =
        new SSHA512PasswordEncoder("}",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier3() {
    final CharSequence rawPassword = "test";
    final SSHA512PasswordEncoder encoder =
        new SSHA512PasswordEncoder("{SSHA-256}",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeLdapEncodedPassword() {
    final CharSequence rawPassword = "test";
    final String encodedPassword = "{SSHA512}9Vg3dzYj8vgMdB46KZzsdhHPbTkn8hIo5XHUWofd/Yo8gO73W3MFymVMcAQZx3D0S1fkLj2f1/FWherDLy2qvDAwMmY3YjA2";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder();
    assertTrue(encoder.matches(rawPassword, encodedPassword));
  }

  @Test
  void challengeWithEmptyPassword() {
    final CharSequence rawPassword = "";
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeWithNullFails() {
    final SSHA512PasswordEncoder encoder = new SSHA512PasswordEncoder();
    final String encoded = encoder.encode(null);
    assertFalse(encoder.matches(null, encoded));
  }
}
