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

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author sius
 */
public class AutoConfigurationTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner().withConfiguration(
          AutoConfigurations.of(PencilAutoConfiguration.class));

  @Test
  void pencil_passwordEncoderBean_should_be_loaded() {
    this.contextRunner.withUserConfiguration(MyConfiguration.class).run((context) -> {
      Assertions.assertThat(context).hasSingleBean(PasswordEncoder.class);
      Assertions.assertThat(context.getBean(PasswordEncoder.class))
          .isSameAs(context.getBean(MyConfiguration.class).passwordEncoder());
    });
  }

  @Configuration
  static class MyConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
      return PencilPasswordEncoderFactory.passwordEncoder();
    }

  }
}