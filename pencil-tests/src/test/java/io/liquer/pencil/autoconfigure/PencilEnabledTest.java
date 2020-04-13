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

import io.liquer.pencil.encoder.SSHA224PasswordEncoder;
import io.liquer.pencil.encoder.SSHA256PasswordEncoder;
import io.liquer.pencil.encoder.SSHA384PasswordEncoder;
import io.liquer.pencil.encoder.SSHA512PasswordEncoder;
import io.liquer.pencil.encoder.SSHAPasswordEncoder;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author sius
 */
@SpringBootTest(classes = {PasswordEncoder.class})
@EnableAutoConfiguration
public class PencilEnabledTest {

  @Autowired
  private PasswordEncoder passwordEncoder;

  @ParameterizedTest(name = "Password: Test should match {0} encodedPassword: {1}")
  @CsvSource({
      "bcrypt  , {bcrypt}$2a$10$8IVIOOBcITG1NGF218vLle6pCOVHWtNNJ378ljV/f8ELvah.6lCC.",
      "scrypt  , {scrypt}$e0801$bH22mYOwpV4XEHasAshNQPDrGLp60D36vFjcr8vevFa+nsB0Sl1oP5zkOzXW0jf+TEoalwOSw+5uk5jNGO3QRA==$zDZvvoCEu+HB0EbyGFgmbrvK7x4JonK/OSXVVxP/rWk=",
      "pbkdf2  , {pbkdf2}9772b0a25dbd6bd7fac7ec8b933ec51b3822d8452b9d2a226378b79ba58763a3b2854fdd13a8b006",
      "ldap    , {ldap}sVoGssCjBP6qNXsBPIO+9CGt7wHEscLU1P1g9Q==",
      "SSHA    , {SSHA}2SU0sErIJ+dQWgBPsY8LQ71vR8R9CK3KU5JcaA==",
      "SSHA1   , {SSHA1}T0Px0ESaRU7wEsEeO7SFztHGVTq66Kk74Qi9dw==",
      "SSHA-1  , {SSHA-1}AWW+ZGX3E0Mq4uPdhG2/3gKqcOJEZbQGJMI+PQ==",
      "SSHA224 , {SSHA224}rOaBkI7J1GUjhf1YX/qe9TT7xAk5lqDFg15DvpK28uGVbJaf",
      "SSHA-224, {SSHA-224}TzlTVB2uobk0nXsE3zC5jDLIYGRMZVTGOr+Nk+/A9lfiASLR",
      "SSHA256 , {SSHA256}uIwxDX6rEZJyeDLQxQVtFbnLRryxTFY6H4CmdK4zdrUl5ATmJbHJbA==",
      "SSHA-256, {SSHA-256}Tz5xUAMQaigghdxYNkp6SMbU7nq91db1rtlKW68XjiY5cH5mUc9n0Q==",
      "SSHA384 , {SSHA384}4JbTnrMYOIwDihdkfxPuDLAR07oA0/Rkav52e/APcZ6uaS+MCtOoKIEYb6FCBrz8JDomc5N9xeE=",
      "SSHA-384, {SSHA-384}GEfRczgipirNvmj1VSzQhe1daUitOcotC+qB18Ke6USKeRB8uB3Ik2HQE+KcwIEcntPDMMMohmo=",
      "SSHA512 , {SSHA512}XPTKozn3qFBn6O4VhYuFDVJDzmzQ9gLvh6FHhcpLjS0VamaS03d+nyeqc0DEAcefepgY8o8ENFS6C9NCZnBASC/KIPh3crfC",
      "SSHA-512, {SSHA-512}ck3hUCXlJ+KIhaOQH3bOEKmR+7+IsagntQOkoQrVWM2ANCoKk5yZA6QiO+bgS1Oo0dad7kDB9SOmVKn3gzRAaDCZ2QhFYbPC",
  })
  void encoded_passwords_should_match(String encodeId, String encodedPassword) {
    final CharSequence expectedPassword = "Test";
    assertTrue(passwordEncoder.matches(expectedPassword, encodedPassword));
  }
}



