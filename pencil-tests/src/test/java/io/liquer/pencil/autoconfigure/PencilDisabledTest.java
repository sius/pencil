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


import io.liquer.pencil.TestApp;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.assertNull;

/**
 * @author sius
 */
@SpringBootTest(classes = { TestApp.class })
@EnableAutoConfiguration
@TestPropertySource(
    properties = {
          "liquer.pencil.enabled=false"
    }
)
@Profile("pencil-disabled")
public class PencilDisabledTest {

  @Autowired(required = false)
  private PencilProperties pencilProperties;

  @Autowired(required = false)
  private PasswordEncoder passwordEncoder;

  @Test
  void pencilProperties_should_be_null() {
    assertNull(pencilProperties);
  }

  @Test
  void passwordEncoder_should_be_null() {
    assertNull(passwordEncoder);
  }
}

