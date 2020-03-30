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

import java.nio.charset.StandardCharsets;

public class XORPasswordEncoderTest {


  @ParameterizedTest(name = "password {0} should match default encoded password {1}")
  @CsvSource({
      "T         , {xor}Cw==            ",
      "Te        , {xor}Czo=            ",
      "Tes       , {xor}Czos            ",
      "Test      , {xor}CzosKw==        ",
      "Test!     , {xor}CzosK34=        ",
      "Test:äöüß#, {xor}CzosK2W7qaOAfA==",
  })
  void password_should_match_default_encoded_password(CharSequence rawPassword, String encodedPassword) {
    final XORPasswordEncoder enc = new XORPasswordEncoder();
    Assertions.assertTrue(enc.matches(rawPassword, encodedPassword));
  }

  @ParameterizedTest(name = "password {0} should match default encoded password {1}")
  @CsvSource({
      "T         , {xor}Cw==            ",
      "Te        , {xor}Czo=            ",
      "Tes       , {xor}Czos            ",
      "Test      , {xor}CzosKw==        ",
      "Test!     , {xor}CzosK34=        ",
      "Test:äöüß#, {xor}CzosK2W7qaOAfA==",
  })
  void password_should_match_encoded_password(CharSequence rawPassword, String encodedPassword) {
    final XORPasswordEncoder enc = new XORPasswordEncoder("_", StandardCharsets.ISO_8859_1);
    Assertions.assertTrue(enc.matches(rawPassword, encodedPassword));
  }

  @Test
  void empty_password_should_match_encoded_password() {
    final String emptyPassword = "";
    final XORPasswordEncoder enc = new XORPasswordEncoder("_", StandardCharsets.ISO_8859_1);
    final String encodedPassword = enc.encode(emptyPassword);
    Assertions.assertTrue(enc.matches(emptyPassword, encodedPassword));
  }
}
