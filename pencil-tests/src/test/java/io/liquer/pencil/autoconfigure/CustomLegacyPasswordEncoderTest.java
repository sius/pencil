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

import io.liquer.pencil.encoder.legacy.SSHA512PasswordEncoder;
import io.liquer.pencil.encoder.legacy.SSHAPasswordEncoder;
import io.liquer.pencil.encoder.legacy.XORPasswordEncoder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@ActiveProfiles({"legacy"})
@SpringBootTest(classes = { CustomLegacyPasswordEncoderConfig.class })
@TestPropertySource(
    properties = {
        "liquer.pencil.enabled = false"
    }
)
@EnableAutoConfiguration
public class CustomLegacyPasswordEncoderTest {


    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void application_context_should_load() {
        Assertions.assertNotNull(passwordEncoder);
        final String password = "test";

        String encoded = new BCryptPasswordEncoder().encode(password);
        Assertions.assertTrue(passwordEncoder.matches(password, "{bcrypt}" + encoded));

        final PasswordEncoder sha = new SSHAPasswordEncoder(KeyGenerators.secureRandom(0));
        encoded = sha.encode(password);
        Assertions.assertTrue(passwordEncoder.matches(password, "{SHA}" + encoded));
        Assertions.assertTrue(sha.matches(password, encoded));
        Assertions.assertTrue(sha.matches(password, "{SHA}" + encoded));

        final PasswordEncoder ssha = new SSHAPasswordEncoder();
        encoded = ssha.encode(password);
        Assertions.assertTrue(passwordEncoder.matches(password, "{SSHA}" + encoded));
        Assertions.assertTrue(ssha.matches(password, encoded));
        Assertions.assertTrue(ssha.matches(password, "{SSHA}" + encoded));

        final PasswordEncoder ssha512 = new SSHA512PasswordEncoder();
        encoded = ssha512.encode(password);
        Assertions.assertTrue(passwordEncoder.matches(password, "{SSHA512}" + encoded));
        Assertions.assertTrue(ssha512.matches(password, encoded));
        Assertions.assertTrue(ssha512.matches(password, "{SSHA512}" + encoded));

        final PasswordEncoder xor = new XORPasswordEncoder();
        encoded = xor.encode(password);
        Assertions.assertTrue(passwordEncoder.matches(password, "{xor}" + encoded));
        Assertions.assertTrue(xor.matches(password, encoded));
        Assertions.assertTrue(xor.matches(password, "{xor}" + encoded));

        final PasswordEncoder scrypt = new SCryptPasswordEncoder();
        encoded = scrypt.encode(password);
        Assertions.assertFalse(passwordEncoder.matches(password, "{scrypt}" + encoded));
        Assertions.assertTrue(scrypt.matches(password, encoded));
        Assertions.assertTrue(scrypt.matches(password, "{scrypt}" + encoded));
    }

}
