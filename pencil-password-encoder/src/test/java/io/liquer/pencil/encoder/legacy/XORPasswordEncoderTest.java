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

package io.liquer.pencil.encoder.legacy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class XORPasswordEncoderTest {

  @Test
  void sanitizeIterations() {
    WithIterations sanitizer =
        new XORPasswordEncoder();

    final int expected = 1;
    final int actual = sanitizer.sanitizeIterations(-100);

    Assertions.assertEquals(expected, actual);
  }


  @Test
  void sanitizeEncodingId() {
    WithEncodingId sanitizer =
        new XORPasswordEncoder();

    final String expected = "xor";
    final String actual = sanitizer.sanitizeEncodingId("([xor}}}");

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void without_EncodingId() {
    PasswordEncoder encoder = new XORPasswordEncoder();
    final String actual = encoder.encode("test");
    Assertions.assertFalse(actual.startsWith("{xor}"));

  }

  @Test
  void with_xor_EncodingId() {
    PasswordEncoder encoder =
        new XORPasswordEncoder().withEncodingId();
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{xor}"));

  }

  @Test
  void with_custom_EncodingId() {
    PasswordEncoder encoder =
        new XORPasswordEncoder().withEncodingId("custom");
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{custom}"));
  }

  @ParameterizedTest(name = "password {0} should match default encoded password {1}")
  @CsvSource({
      "T         , {xor}Cw==                 ",
      "Te        , {xor}Czo=                 ",
      "Tes       , {xor}Czos                 ",
      "Test      , {xor}CzosKw==             ",
      "Test!     , {xor}CzosK34=             ",
      "Test:äöüß#, {xor}CzosK2Wc+5zpnOOcwHw= ",
      "T         ,      Cw==                 ",
      "Te        ,      Czo=                 ",
      "Tes       ,      Czos                 ",
      "Test      ,      CzosKw==             ",
      "Test!     ,      CzosK34=             ",
      "Test:äöüß#,      CzosK2Wc+5zpnOOcwHw= ",
  })
  void password_should_match_default_encoded_password(CharSequence rawPassword, String encodedPassword) {
    final XORPasswordEncoder enc = new XORPasswordEncoder();
    Assertions.assertTrue(enc.matches(rawPassword, encodedPassword));
  }

  @ParameterizedTest(name = "password {0} should match default encoded password {1}")
  @CsvSource({
      "T         , {xor}Cw==                 , ISO-8859-1",
      "Te        , {xor}Czo=                 , ISO-8859-1",
      "Tes       , {xor}Czos                 , ISO-8859-1",
      "Test      , {xor}CzosKw==             , ISO-8859-1",
      "Test!     , {xor}CzosK34=             , ISO-8859-1",
      "Test:äöüß#, {xor}CzosK2W7qaOAfA==     , ISO-8859-1",
      "Test:äöüß#, {xor}CzosK2Wc+5zpnOOcwHw= , UTF-8     ",
      "T         ,      Cw==                 , ISO-8859-1",
      "Te        ,      Czo=                 , ISO-8859-1",
      "Tes       ,      Czos                 , ISO-8859-1",
      "Test      ,      CzosKw==             , ISO-8859-1",
      "Test!     ,      CzosK34=             , ISO-8859-1",
      "Test:äöüß#,      CzosK2W7qaOAfA==     , ISO-8859-1",
      "Test:äöüß#,      CzosK2Wc+5zpnOOcwHw= , UTF-8     ",
  })
  void password_should_match_encoded_password(CharSequence rawPassword, String encodedPassword, Charset charset) {
    final XORPasswordEncoder enc = new XORPasswordEncoder(charset);
    Assertions.assertTrue(enc.matches(rawPassword, encodedPassword));
  }

  @Test
  void empty_password_should_match_encoded_password() {
    final XORPasswordEncoder enc = new XORPasswordEncoder();
    final String encodedPassword = enc.encode("");
    Assertions.assertTrue(enc.matches("", encodedPassword));
  }

  @Test
  void null_password_should_not_match() {
    final XORPasswordEncoder enc = new XORPasswordEncoder();
    final String encodedPassword = enc.encode(null);
    Assertions.assertFalse(enc.matches(null, encodedPassword));
  }
}
