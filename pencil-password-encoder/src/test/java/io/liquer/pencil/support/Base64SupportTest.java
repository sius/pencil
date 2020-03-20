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

package io.liquer.pencil.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author sius
 */
public class Base64SupportTest {

  @Test
  public void test64Encode() {
    assertEquals("", Base64Support.base64Encode(new byte[0]));
    assertEquals("", Base64Support.base64Encode("".getBytes()));
    assertEquals("Zg==", Base64Support.base64Encode("f".getBytes()));
    assertEquals("Zm8=", Base64Support.base64Encode("fo".getBytes()));
    assertEquals("Zm9v", Base64Support.base64Encode("foo".getBytes()));
    assertEquals("Zm9vYg==", Base64Support.base64Encode("foob".getBytes()));
    assertEquals("Zm9vYmE=", Base64Support.base64Encode("fooba".getBytes()));
    assertEquals("Zm9vYmFy", Base64Support.base64Encode("foobar".getBytes()));
  }

  @Test
  public void base64UfsEncode() {
    assertEquals("", Base64Support.base64Encode("".getBytes()));
    assertEquals("Zg==", Base64Support.base64Encode("f".getBytes()));
    assertEquals("Zm8=", Base64Support.base64Encode("fo".getBytes()));
    assertEquals("Zm9v", Base64Support.base64Encode("foo".getBytes()));
    assertEquals("Zm9vYg==", Base64Support.base64Encode("foob".getBytes()));
    assertEquals("Zm9vYmE=", Base64Support.base64Encode("fooba".getBytes()));
    assertEquals("Zm9vYmFy", Base64Support.base64Encode("foobar".getBytes()));
  }

  @Test
  public void base64UrlEncode() {
    assertEquals("", Base64Support.base64UrlEncode("".getBytes()));
    assertEquals("Zg", Base64Support.base64UrlEncode("f".getBytes()));
    assertEquals("Zm8", Base64Support.base64UrlEncode("fo".getBytes()));
    assertEquals("Zm9v", Base64Support.base64UrlEncode("foo".getBytes()));
    assertEquals("Zm9vYg", Base64Support.base64UrlEncode("foob".getBytes()));
    assertEquals("Zm9vYmE", Base64Support.base64UrlEncode("fooba".getBytes()));
    assertEquals("Zm9vYmFy", Base64Support.base64UrlEncode("foobar".getBytes()));
  }

  @ParameterizedTest(name = "base64 encoded value {0} represents decoded value {1}")
  @CsvSource({
      "TQ==                         , M                   ",
      "TQ                           , M                   ",
      "TWE=                         , Ma                  ",
      "TWE                          , Ma                  ",
      "TWFu                         , Man                 ",
      "c3VyZS4=                     , sure.               ",
      "c3VyZS4                      , sure.               ",
      "ZWFzdXJlLg==                 , easure.             ",
      "ZWFzdXJlLg==                 , easure.             ",
      "YXN1cmUu                     , asure.              ",
      "YW55IGNhcm5hbCBwbGVhc3VyZS4= , any carnal pleasure.",
      "YW55IGNhcm5hbCBwbGVhc3VyZS4  , any carnal pleasure."
  })
  public void base64Decode_should_succeed(String encoded, String expected) {
    final String actual = new String(Base64Support.base64Decode(encoded), StandardCharsets.UTF_8);
    assertEquals(expected, actual);
  }
}
