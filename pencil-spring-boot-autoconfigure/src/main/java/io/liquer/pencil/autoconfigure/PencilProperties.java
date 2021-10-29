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
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

@Component
@ConfigurationProperties(prefix = "liquer.pencil")
@ConditionalOnExpression("${liquer.pencil.enabled:true}")
public class PencilProperties {

  /**
   * Whether to enable the auto-configuration.
   * (default: true)
   */
  private boolean enabled = true;

  /**
   * The default encode id.
   * (default: bcrypt)
   */
  private String defaultEncodeId = "bcrypt";

  /**
   * Whether to base64 encode URL and file safe.
   * (default: false)
   */
  private boolean ufSafe = false;

  /**
   * Whether to base64 encode without padding.
   * (default: false)
   */
  private boolean noPadding = false;

  /**
   * The salt size in bytes.
   * (default: 8)
   */
  private int saltSize = 8;

  /**
   * Whether to support unsalted passwords.
   * (default: true)
   */
  private boolean supportUnsaltedPasswords = true;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean state) {
    enabled = state;
  }

  public boolean isUfSafe() {
    return ufSafe;
  }

  public void setUfSafe(boolean ufSafe) {
    this.ufSafe = ufSafe;
  }

  public boolean isNoPadding() {
    return noPadding;
  }

  public void setNoPadding(boolean noPadding) {
    this.noPadding = noPadding;
  }

  public int getSaltSize() {
    return saltSize;
  }

  public void setSaltSize(int saltSize) {
    this.saltSize = saltSize;
  }

  public String getDefaultEncodeId() {
    return defaultEncodeId;
  }

  public void setDefaultEncodeId(String defaultEncodeId) {
    this.defaultEncodeId = defaultEncodeId;
  }

  public boolean isSupportUnsaltedPasswords() {
    return supportUnsaltedPasswords;
  }

  public void setSupportUnsaltedPasswords(boolean supportUnsaltedPasswords) {
    this.supportUnsaltedPasswords = supportUnsaltedPasswords;
  }
}
