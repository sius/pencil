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

import io.liquer.pencil.encoder.WithEncodingId;
import io.liquer.pencil.encoder.WithIterations;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import static io.liquer.pencil.encoder.TestHelper.log;
import static org.junit.jupiter.api.Assertions.*;

/**
 * @author sius
 */
public class MD5PasswordEncoderTest {


  @Test
  void sanitizeIterations() {
    WithIterations sanitizer =
        new MD5PasswordEncoder();

    final int expected = 1;
    final int actual = sanitizer.sanitizeIterations(-100);

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void sanitizeEncodingId() {
    WithEncodingId sanitizer =
        new MD5PasswordEncoder();

    final String expected = "SSHA";
    final String actual = sanitizer.sanitizeEncodingId("([SSHA}}}");

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void without_EncodingId() {
    PasswordEncoder encoder = new MD5PasswordEncoder();
    final String actual = encoder.encode("test");
    Assertions.assertFalse(actual.startsWith("{SSHA}"));

  }

  @Test
  void with_MD5_EncodingId() {
    PasswordEncoder encoder =
        new MD5PasswordEncoder().withEncodingId();
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{MD5}"));
  }


  @Test
  void with_custom_EncodingId() {
    PasswordEncoder encoder =
        new MD5PasswordEncoder().withEncodingId("custom");
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{custom}"));
  }

  @Test
  void matches_withNullFails() {
    final PasswordEncoder md5Encoder = new MD5PasswordEncoder().withEncodingId();

    final String encoded = md5Encoder.encode(null);
    log(encoded);
    assertFalse(md5Encoder.matches(null, encoded));
  }


  @Test
  void matches_withEmptyPasswordSucceeds() {
    final CharSequence rawPassword = "";
    final PasswordEncoder md5Encoder = new MD5PasswordEncoder().withEncodingId();

    final String encoded = md5Encoder.encode(rawPassword);
    log(encoded);
    assertTrue(md5Encoder.matches(rawPassword, encoded));
  }


  @Test
  void matches_withoutSaltSucceeds() {
    final CharSequence rawPassword = "test";
    final PasswordEncoder encoder =
      new MD5PasswordEncoder(KeyGenerators.secureRandom(0))
        .withEncodingId();

    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void matches_Succeeds() {
    final CharSequence password = "Test";
    final PasswordEncoder md5 = new MD5PasswordEncoder().withEncodingId();

    assertTrue(md5.matches(password, md5.encode(password)));
  }

  @Test
  void matches_withSaltAndMultipleIterationsBehaveCorrect() {
    final CharSequence password = "Test";
    final PasswordEncoder md5_1_iteration = new MD5PasswordEncoder()
        .withEncodingId()
        .withIterations(1);

    final PasswordEncoder md5_2_iterations = new MD5PasswordEncoder()
        .withEncodingId()
        .withIterations(2);


    final String encoded_1_iteration = md5_1_iteration.encode(password);
    final String encoded_2_iterations = md5_2_iterations.encode(password);
    assertTrue(md5_1_iteration.matches(password, encoded_1_iteration));
    assertFalse(md5_2_iterations.matches(password, encoded_1_iteration));

    assertTrue(md5_2_iterations.matches(password, encoded_2_iterations));
    assertFalse(md5_1_iteration.matches(password, encoded_2_iterations));
  }



















  @Test
  void challengeWithEmptyPassword() {
    final CharSequence rawPassword = "";
    final MD5PasswordEncoder encoder = new MD5PasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeWithNullFails() {
    final MD5PasswordEncoder encoder = new MD5PasswordEncoder();
    final String encoded = encoder.encode(null);
    assertFalse(encoder.matches(null, encoded));
  }
}
