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

package io.liquer.pencil.encoder;

public interface WithSecurityAdvice {

    LogSecurityAdvice DEFAULT_SECURITY_ADVICE =
        (logger, encoderInfo, hashInfo) -> {
            if (hashInfo.getSaltSize() < 8) {
                logger.warn("Unsecure passwordHash algorithm {} or saltSize has been matched. " +
                        "Update user password and passwordHash algorithm to meet current security standards!",
                    hashInfo.getEncodingId());
            }
        };

    PencilPasswordEncoder withSecurityAdvice(boolean giveAdvice, LogSecurityAdvice securityAdvice);

    default PencilPasswordEncoder withSecurityAdvice(boolean giveAdvice) {
        return withSecurityAdvice(giveAdvice, DEFAULT_SECURITY_ADVICE);
    }
}
