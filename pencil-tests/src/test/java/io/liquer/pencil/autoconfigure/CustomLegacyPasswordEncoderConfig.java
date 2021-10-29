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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@Profile("legacy")
@Configuration
public class CustomLegacyPasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {

        final Map<String, PasswordEncoder> encoders = new HashMap<>();
        final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
        encoders.put("bcrypt", bcrypt);
        encoders.put("SHA", new SSHAPasswordEncoder(KeyGenerators.secureRandom(0)));
        encoders.put("SSHA", new SSHAPasswordEncoder());
        encoders.put("SSHA512", new SSHA512PasswordEncoder());
        encoders.put("xor", new XORPasswordEncoder());

        final DelegatingPasswordEncoder ret = new DelegatingPasswordEncoder("bcrypt", encoders);
        ret.setDefaultPasswordEncoderForMatches(bcrypt);
        return ret;
    }
}
