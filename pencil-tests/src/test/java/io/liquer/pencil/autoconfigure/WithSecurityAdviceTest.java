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

package io.liquer.pencil.autoconfigure;

import io.liquer.pencil.TestApp;
import io.liquer.pencil.encoder.WithEncodingId;
import io.liquer.pencil.encoder.WithIterations;
import io.liquer.pencil.encoder.legacy.MD5PasswordEncoder;
import io.liquer.pencil.encoder.legacy.SSHA512PasswordEncoder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author sius
 */
@SpringBootTest(classes = { TestApp.class })
@EnableAutoConfiguration
@TestPropertySource(
    properties = {
        "liquer.pencil.enabled=true",
        "liquer.pencil.with-security-advice=true"
    }
)
public class WithSecurityAdviceTest {

  @Test
  void matches_MD5_shoul_create_a_security_advice() {
    final CharSequence rawPassword = "test";
    final PasswordEncoder encoder = new MD5PasswordEncoder(KeyGenerators.secureRandom(7))
        .withSecurityAdvice(true);
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }
}
