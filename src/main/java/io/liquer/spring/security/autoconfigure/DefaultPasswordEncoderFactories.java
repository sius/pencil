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
 */

package io.liquer.spring.security.autoconfigure;

import io.liquer.spring.security.encoder.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * @author sius
 */
public class DefaultPasswordEncoderFactories {

    /**
     * deprecated PasswordEncoders has been removed
     * encoders.put("noop", NoOpPasswordEncoder.getInstance());
     * encoders.put("MD4", new Md4PasswordEncoder());
     * encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
     * encoders.put("SHA1", new MessageDigestPasswordEncoder("SHA-1"));
     * encoders.put("SHA-1", new MessageDigestPasswordEncoder("SHA-1"));
     * encoders.put("SHA-256", new MessageDigestPasswordEncoder("SHA-256"));
     * encoders.put("SHA256", new StandardPasswordEncoder());
     * LdapShaPasswordEncoder has been replaced by SSHAPasswordEncoder
     *
     * @return the DelegationPasswordEncoder
     */
    static PasswordEncoder passwordEncoder() {
        final String defaultEncodeId = "bcrypt";
        return passwordEncoder(defaultEncodeId);
    }

    static PasswordEncoder passwordEncoder(String encodeId) {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();

        encoders.put("bcrypt", bcrypt);
        encoders.put("scrypt", new SCryptPasswordEncoder());
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());

        final PasswordEncoder ssha = new SSHAPasswordEncoder("", 8);
        encoders.put("ldap", ssha);
        encoders.put("SSHA", ssha);
        encoders.put("SSHA1", ssha);
        encoders.put("SSHA-1", ssha);

        final PasswordEncoder ssha224 = new SSHA224PasswordEncoder("", 8);
        encoders.put("SSHA224", ssha224);
        encoders.put("SSHA-224", ssha224);

        final PasswordEncoder ssha256 = new SSHA256PasswordEncoder("", 8);
        encoders.put("SSHA256", ssha256);
        encoders.put("SSHA-256", ssha256);

        final PasswordEncoder ssha384 = new SSHA384PasswordEncoder("", 8);
        encoders.put("SSHA384", ssha384);
        encoders.put("SSHA-384", ssha384);

        final PasswordEncoder ssha512 = new SSHA512PasswordEncoder("", 8);
        encoders.put("SSHA512", ssha512);
        encoders.put("SSHA-512", ssha512);

        final DelegatingPasswordEncoder ret = new DelegatingPasswordEncoder(encodeId, encoders);
        ret.setDefaultPasswordEncoderForMatches(bcrypt);
        return ret;
    }

}