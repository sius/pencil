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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static io.liquer.pencil.encoder.TestHelper.log;
import static org.junit.jupiter.api.Assertions.*;

/**
 * @author sius
 */
public class SSHAPasswordEncoderTest {


  @Test
  void sanitizeIterations() {
    WithIterations sanitizer =
        new SSHAPasswordEncoder();

    final int expected = 1;
    final int actual = sanitizer.sanitizeIterations(-100);

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void sanitizeEencodingId() {
    WithEncodingId sanitizer =
        new SSHAPasswordEncoder();

    final String expected = "SSHA";
    final String actual = sanitizer.sanitizeEncodingId("([SSHA}}}");

    Assertions.assertEquals(expected, actual);
  }

  @Test
  void without_EncodingId() {
    PasswordEncoder encoder = new SSHAPasswordEncoder();
    final String actual = encoder.encode("test");
    Assertions.assertFalse(actual.startsWith("{SSHA}"));

  }

  @Test
  void with_SSHA_EncodingId() {
    PasswordEncoder encoder =
        new SSHAPasswordEncoder().withEncodingId();
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{SSHA}"));

  }

  @Test
  void with_SHA_EncodingId() {
    PasswordEncoder encoder =
        new SSHAPasswordEncoder(KeyGenerators.secureRandom(0)).withEncodingId();
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{SHA}"));
  }

  @Test
  void with_custom_EncodingId() {
    PasswordEncoder encoder =
        new SSHAPasswordEncoder().withEncodingId("custom");
    final String actual = encoder.encode("test");
    Assertions.assertTrue(actual.startsWith("{custom}"));
  }

  @Test
  @SuppressWarnings("deprecation")
  void matches_withNullFails() {
    final CharSequence rawPassword = null;
    final PasswordEncoder sshaEncoder = new SSHAPasswordEncoder().withEncodingId();
    final PasswordEncoder ldapEncoder = new LdapShaPasswordEncoder();

    final String encoded = sshaEncoder.encode(rawPassword);
    log(encoded);
    assertFalse(sshaEncoder.matches(rawPassword, encoded));
    assertThrows(NullPointerException.class, () -> ldapEncoder.matches(rawPassword, encoded));

    assertThrows(NullPointerException.class, () -> ldapEncoder.encode(rawPassword));
  }


  @Test
  @SuppressWarnings("deprecation")
  void matches_withEmptyPasswordSucceeds() {
    final CharSequence rawPassword = "";
    final PasswordEncoder sshaEncoder = new SSHAPasswordEncoder().withEncodingId();
        final PasswordEncoder ldapEncoder = new LdapShaPasswordEncoder();

    final String encoded = sshaEncoder.encode(rawPassword);
    log(encoded);
    assertTrue(sshaEncoder.matches(rawPassword, encoded));
    assertTrue(ldapEncoder.matches(rawPassword, encoded));

    final String encoded2 = ldapEncoder.encode(rawPassword);
    log(encoded2);
    assertTrue(sshaEncoder.matches(rawPassword, encoded2));
    assertTrue(ldapEncoder.matches(rawPassword, encoded2));
  }


  @Test
  @SuppressWarnings("deprecation")
  void matches_withoutSaltSucceeds() {
    final CharSequence rawPassword = "test";
    final PasswordEncoder encoder =
      new SSHAPasswordEncoder(KeyGenerators.secureRandom(0))
        .withEncodingId();
    final LdapShaPasswordEncoder ldapEncoder =
        new LdapShaPasswordEncoder(KeyGenerators.secureRandom(0));

    final String encoded = encoder.encode(rawPassword);
    log(encoded);
    assertTrue(encoder.matches(rawPassword, encoded));
    assertTrue(ldapEncoder.matches(rawPassword, encoded));


    final String encoded2 = ldapEncoder.encode(rawPassword);
    assertTrue(encoder.matches(rawPassword, encoded2));
    assertTrue(ldapEncoder.matches(rawPassword, encoded2));

  }

  @Test
  @SuppressWarnings("deprecation")
  void matches_Succeeds() {
    final CharSequence password = "Test";
    final PasswordEncoder ssha = new SSHAPasswordEncoder().withEncodingId();
    final PasswordEncoder ldap = new LdapShaPasswordEncoder();

    assertTrue(ssha.matches(password, ldap.encode(password)));
    assertTrue(ldap.matches(password, ssha.encode(password)));
  }

  @Test
  @SuppressWarnings("deprecation")
  void matches_withLongPasswordSucceeds() {
    final CharSequence password = "LirimLarumLöffelstielkbaajfajgalkjglbhchqprävwnmcrcwlrmj3mjrac";
    final PasswordEncoder ssha = new SSHAPasswordEncoder().withEncodingId();
    final PasswordEncoder ldap = new LdapShaPasswordEncoder();

    assertTrue(ssha.matches(password, ssha.encode(password)));
    assertTrue(ssha.matches(password, ldap.encode(password)));
    assertTrue(ldap.matches(password, ldap.encode(password)));
    assertTrue(ldap.matches(password, ssha.encode(password)));
  }

  @Test
  void matches_withSaltAndMultipleIterationsBehaveCorrect() {
    final CharSequence password = "Test";
    final PasswordEncoder ssha_1_iteration = new SSHAPasswordEncoder()
        .withEncodingId()
        .withIterations(1);

    final PasswordEncoder ssha_2_iterations = new SSHAPasswordEncoder()
        .withEncodingId()
        .withIterations(2);


    final String encoded_1_iteration = ssha_1_iteration.encode(password);
    final String encoded_2_iterations = ssha_2_iterations.encode(password);
    assertTrue(ssha_1_iteration.matches(password, encoded_1_iteration));
    assertFalse(ssha_2_iterations.matches(password, encoded_1_iteration));

    assertTrue(ssha_2_iterations.matches(password, encoded_2_iterations));
    assertFalse(ssha_1_iteration.matches(password, encoded_2_iterations));
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
