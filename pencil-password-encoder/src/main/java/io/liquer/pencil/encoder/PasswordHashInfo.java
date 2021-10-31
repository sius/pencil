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

public interface PasswordHashInfo {

    /**
     * Get the identifier part <code>"{<encodingId>}"</code> or an empty <code>String</code>.
     *
     * @return the identifier part or an empty <code>String</code>
     */
    String getIdentifier();

    /**
     * Get the encodingId from the identifier part or an empty <code>String</code>.
     *
     * @return the encodingId or an empty <code>String</code>
     */
    String getEncodingId();

    /**
     * Get the calculated salt size.
     * A negative value indicates an invalid hash.
     *
     * @return the calculated salt size
     */
    int getSaltSize();
}
