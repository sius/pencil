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

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * The auto-configuration for the custom PasswordEncoder Bean.
 * @author sius
 */
@Configuration
@ComponentScan(basePackageClasses= { PencilProperties.class })
@ConditionalOnExpression("${liquer.pencil.enabled:true}")
public class PencilAutoConfiguration {

  /**
   * Custom DelegatingPasswordEncoder Bean.
   * @return the custom DelegatingPasswordEncoder
   */
  @Bean
  public PasswordEncoder passwordEncoder(PencilProperties properties) {
    return PencilPasswordEncoderFactory.passwordEncoder(properties);
  }
}
