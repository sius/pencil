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

package io.liquer.pencil.autoconfigure;

import java.util.HashMap;
import java.util.Map;

import io.liquer.pencil.encoder.legacy.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import static io.liquer.pencil.encoder.legacy.EncodingIds.*;

/**
 * Custom Factory for Spring Boot PasswordEncoder
 * - bcrypt (`org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`)
 * - scrypt (`org.springframework.security.crypto.scrypt.SCryptPasswordEncoder`)
 * - pbkdf2 (`org.springframework.security.crypto.password.Pbkdf2PasswordEncoder`)
 * - ldap, SSHA, SSHA1, SSHA-1 (`LdapShaPasswordEncoder` compatible implementation of the Salted Secure Hash Algorithm)
 * - SSHA224, SSHA-224
 * - SSHA256, SSHA-256
 * - SSHA384, SSHA-384
 * - SHAA512, SSHA-512.
 *
 * @author sius
 */
public final class PencilPasswordEncoderFactory {

  /**
   * 'Deprecated' PasswordEncoders has been removed.
   * Removed encoders:
   * encoders.put("noop", NoOpPasswordEncoder.getInstance());
   * encoders.put("MD4", new Md4PasswordEncoder());
   * encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
   * encoders.put("SHA1", new MessageDigestPasswordEncoder("SHA-1"));
   * encoders.put("SHA-1", new MessageDigestPasswordEncoder("SHA-1"));
   * encoders.put("SHA-256", new MessageDigestPasswordEncoder("SHA-256"));
   * encoders.put("SHA256", new StandardPasswordEncoder());
   * LdapShaPasswordEncoder has been replaced by SSHAPasswordEncoder
   *
   * @param pencilProperties  the PencilProperties
   * @return t he DelegationPasswordEncoder
   */
  static PasswordEncoder passwordEncoder(final PencilProperties pencilProperties) {
    final Map<String, PasswordEncoder> encoders = new HashMap<>();
    final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();

    encoders.put("bcrypt", bcrypt);
    encoders.put("scrypt", new SCryptPasswordEncoder());
    encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());

    final int iterations = 1;
    final BytesKeyGenerator saltGenerator =
        KeyGenerators.secureRandom(pencilProperties.getSaltSize());

    final PasswordEncoder ssha = new SSHAPasswordEncoder(
        saltGenerator, iterations,
        pencilProperties.isUfSafe(),
        pencilProperties.isNoPadding());
    encoders.put(SSHA, ssha);
    encoders.put(SSHA1, ssha);
    encoders.put(SSHA_1, ssha);

    final PasswordEncoder ssha224 = new SSHA224PasswordEncoder(
        saltGenerator, iterations,
        pencilProperties.isUfSafe(),
        pencilProperties.isNoPadding());
    encoders.put(SSHA224, ssha224);
    encoders.put(SSHA_224, ssha224);

    final PasswordEncoder ssha256 = new SSHA256PasswordEncoder(
          saltGenerator, iterations,
          pencilProperties.isUfSafe(),
          pencilProperties.isNoPadding());
    encoders.put(SSHA256, ssha256);
    encoders.put(SSHA_256, ssha256);

    final PasswordEncoder ssha384 = new SSHA384PasswordEncoder(
            saltGenerator, iterations,
            pencilProperties.isUfSafe(),
            pencilProperties.isNoPadding());
    encoders.put(SSHA384, ssha384);
    encoders.put(SSHA_384, ssha384);

    final PasswordEncoder ssha512 = new SSHA512PasswordEncoder(
            saltGenerator, iterations,
            pencilProperties.isUfSafe(),
            pencilProperties.isNoPadding());
    encoders.put(SSHA512, ssha512);
    encoders.put(SSHA_512, ssha512);


    if (pencilProperties.isSupportUnsaltedPasswords()) {

      final BytesKeyGenerator unsaltedGenerator =
          KeyGenerators.secureRandom(0);

      final PasswordEncoder ldap = new SSHAPasswordEncoder(
          unsaltedGenerator, iterations,
          pencilProperties.isUfSafe(),
          pencilProperties.isNoPadding());
      encoders.put(LDAP, ldap);
      encoders.put(SHA, ldap);
      encoders.put(SHA1, ldap);
      encoders.put(SHA_1, ldap);

      final PasswordEncoder sha224 = new SSHA224PasswordEncoder(
          unsaltedGenerator, iterations,
          pencilProperties.isUfSafe(),
          pencilProperties.isNoPadding());
      encoders.put(SHA224, sha224);
      encoders.put(SHA_224, sha224);

      final PasswordEncoder sha256 = new SSHA256PasswordEncoder(
          unsaltedGenerator, iterations,
          pencilProperties.isUfSafe(),
          pencilProperties.isNoPadding());
      encoders.put(SHA256, sha256);
      encoders.put(SHA_256, sha256);

      final PasswordEncoder sha384 = new SSHA384PasswordEncoder(
          unsaltedGenerator, iterations,
          pencilProperties.isUfSafe(),
          pencilProperties.isNoPadding());
      encoders.put(SHA384, sha384);
      encoders.put(SHA_384, sha384);

      final PasswordEncoder sha512 = new SSHA512PasswordEncoder(
          unsaltedGenerator, iterations,
          pencilProperties.isUfSafe(),
          pencilProperties.isNoPadding());
      encoders.put(SHA512, ssha512);
      encoders.put(SHA_512, ssha512);
    }


    final boolean containsKey = encoders.containsKey(pencilProperties.getDefaultEncodeId());
    final PasswordEncoder defaultPasswordEncoder = containsKey
            ? encoders.get(pencilProperties.getDefaultEncodeId())
            : bcrypt;
    final String defaultEncodeId = containsKey
            ? pencilProperties.getDefaultEncodeId()
            : "bcrypt";
    final DelegatingPasswordEncoder ret = new DelegatingPasswordEncoder(defaultEncodeId, encoders);
    ret.setDefaultPasswordEncoderForMatches(defaultPasswordEncoder);
    return ret;
  }

  private PencilPasswordEncoderFactory() { }
}
