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
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.KeyGenerator;

import static io.liquer.pencil.encoder.TestHelper.log;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author sius
 */
@SuppressWarnings("deprecated")
public class SSHAPasswordEncoderTest {


  @Test
  void encodeWithoutSalt() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder("{SHA}", 0);
    final LdapShaPasswordEncoder ldapEncoder = new LdapShaPasswordEncoder(KeyGenerators.secureRandom(0));

    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertTrue(encoded.startsWith(SSHAPasswordEncoder.SHA_IDENTIFIER));
    assertTrue(encoder.matches(rawPassword, encoded));
    assertTrue(ldapEncoder.matches(rawPassword, encoded));


    final String encoded2 = ldapEncoder.encode(rawPassword);
    assertTrue(encoded2.startsWith(SSHAPasswordEncoder.SHA_IDENTIFIER));
    assertTrue(encoder.matches(rawPassword, encoded2));
    assertTrue(ldapEncoder.matches(rawPassword, encoded2));

  }

  @Test
  void encodeWithShortIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertTrue(encoded.startsWith(SSHAPasswordEncoder.SSHA_SHORT_IDENTIFIER));
  }

  @Test
  void encodeWithLongIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder(
        SSHAPasswordEncoder.SSHA_LONG_IDENTIFIER,
        8 );
    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertTrue(encoded.startsWith(SSHAPasswordEncoder.SSHA_LONG_IDENTIFIER));

  }

  @Test
  void encodeWithEmptyIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder =
        new SSHAPasswordEncoder("", 8);
    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertEquals(-1, encoded.indexOf('{'));
    assertEquals(-1, encoded.indexOf('}'));
  }

  @Test
  void challengeRawPasswordWithLongIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithShortIdentifier() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder(
        SSHAPasswordEncoder.SSHA_SHORT_IDENTIFIER,
        8 );
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithEmptyIdentifier1() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder =
        new SSHAPasswordEncoder("",8);
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithEmptyIdentifier2() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder =
        new SSHAPasswordEncoder("{}",8);
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier1() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder =
        new SSHAPasswordEncoder("{",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier2() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder =
        new SSHAPasswordEncoder("}",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeRawPasswordWithInvalidIdentifier3() {
    final CharSequence rawPassword = "test";
    final SSHAPasswordEncoder encoder =
        new SSHAPasswordEncoder("{SSHA-512}",8);
    final String encoded = encoder.encode(rawPassword);
    assertFalse(encoder.matches(rawPassword, encoded));
  }

  @Test
  @SuppressWarnings("deprecation")
  void ssha_and_ldap_should_be_compatible() {
    final CharSequence password = "Test";
    final PasswordEncoder ssha = new SSHAPasswordEncoder();
    final PasswordEncoder ldap = new LdapShaPasswordEncoder();

    assertTrue(ssha.matches(password, ldap.encode(password)));
    assertTrue(ldap.matches(password, ssha.encode(password)));
  }

  @Test
  void challengeWithEmptyPassword() {
    final CharSequence rawPassword = "";
    final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder();
    final String encoded = encoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded));
  }

  @Test
  void challengeWithNullFails() {
    final SSHAPasswordEncoder encoder = new SSHAPasswordEncoder();
    final String encoded = encoder.encode(null);
    assertFalse(encoder.matches(null, encoded));
  }
}
