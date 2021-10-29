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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author sius
 */
public class AutoConfigurationTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(PencilAutoConfiguration.class));

  @Test
  void enabled_passwordEncoderBean_should_be_loaded() {
    this.contextRunner
        .withPropertyValues("liquer.pencil.enabled=true")
        .withUserConfiguration(MyConfiguration.class).run((context) -> {
      Assertions.assertThat(context).hasSingleBean(PasswordEncoder.class);
      Assertions.assertThat(context.getBean(PasswordEncoder.class))
          .isSameAs(context.getBean(MyConfiguration.class).passwordEncoder);
    });
  }

  @Test
  void without_conditional_property_passwordEncoderBean_should_be_loaded() {
    this.contextRunner
        .withUserConfiguration(MyConfiguration.class).run((context) -> {
      Assertions.assertThat(context).hasSingleBean(PasswordEncoder.class);
      Assertions.assertThat(context.getBean(PasswordEncoder.class))
          .isSameAs(context.getBean(MyConfiguration.class).passwordEncoder);
    });
  }

  @Test
  void disabled_passwordEncoderBean_should_not_be_loaded() {
    this.contextRunner
        .withPropertyValues("liquer.pencil.enabled=false")
        .withUserConfiguration(MyConfiguration.class).run((context) -> {
      Assertions.assertThat(context).doesNotHaveBean(PasswordEncoder.class);
      Assertions.assertThat(context.getBean(MyConfiguration.class).passwordEncoder).isNull();
    });
  }

  @Test
  void enabled_passwordEncoderBean_should_be_loaded_with_default_properties() {
    this.contextRunner
            .withUserConfiguration(MyConfiguration.class).run((context) -> {
      Assertions.assertThat(context).hasSingleBean(PasswordEncoder.class);
      Assertions.assertThat(context.getBean(PasswordEncoder.class))
              .isSameAs(context.getBean(MyConfiguration.class).passwordEncoder);
      Assertions.assertThat(false)
              .isSameAs(context.getBean(MyConfiguration.class).ufSafe);
      Assertions.assertThat(false)
              .isSameAs(context.getBean(MyConfiguration.class).noPadding);
      Assertions.assertThat(8)
              .isSameAs(context.getBean(MyConfiguration.class).saltSize);
      Assertions.assertThat(true)
          .isSameAs(context.getBean(MyConfiguration.class).supportUnsaltedPasswords);
    });
  }

  @Test
  void enabled_passwordEncoderBean_should_be_loaded_with_custom_properties() {
    this.contextRunner
            .withPropertyValues("liquer.pencil.uf-safe=true")
            .withPropertyValues("liquer.pencil.no-padding=true")
            .withPropertyValues("liquer.pencil.salt-size=16")
            .withPropertyValues("liquer.pencil.support-unsalted-passwords=false")
            .withUserConfiguration(MyConfiguration.class).run((context) -> {
      Assertions.assertThat(context).hasSingleBean(PasswordEncoder.class);
      Assertions.assertThat(context.getBean(PasswordEncoder.class))
              .isSameAs(context.getBean(MyConfiguration.class).passwordEncoder);
      Assertions.assertThat(true)
              .isSameAs(context.getBean(MyConfiguration.class).ufSafe);
      Assertions.assertThat(true)
              .isSameAs(context.getBean(MyConfiguration.class).noPadding);
      Assertions.assertThat(16)
              .isSameAs(context.getBean(MyConfiguration.class).saltSize);
      Assertions.assertThat(false)
          .isSameAs(context.getBean(MyConfiguration.class).supportUnsaltedPasswords);
    });
  }

  @Configuration
  static class MyConfiguration {

    @Autowired(required = false)
    private PasswordEncoder passwordEncoder;

    @Value("${liquer.pencil.uf-safe:false}")
    private boolean ufSafe;

    @Value("${liquer.pencil.no-padding:false}")
    private boolean noPadding;

    @Value("${liquer.pencil.salt-size:8}")
    private int saltSize;

    @Value("${liquer.pencil.support-unsalted-passwords:true}")
    private boolean supportUnsaltedPasswords;
  }
}
