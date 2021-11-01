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

public interface PasswordEncoderInfo {

    /**
     * Get the iteration value of how many times
     * the encoding algorithm will be applied.
     *
     * @return the iterations value
     */
    int getIterations();

    /**
     * Get the hash size of the calculated password (without salt) or
     * -1 if the algorithm has no defined hash size (e.g.: xor).
     *
     * @return the hash size of the calculated password (without salt) or
     *          -1 if the algorithm has no defined hash size (e.g.: xor)
     */
    default int getHashSize() { return -1; }

    String getAlgorithm();
}
