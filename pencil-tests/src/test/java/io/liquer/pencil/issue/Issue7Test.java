package io.liquer.pencil.issue;

import io.liquer.pencil.encoder.SSHA512PasswordEncoder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class Issue7Test {

    @Test
    void iso8859_1_ssha512_encoded_passwords_should_match() {
        final CharSequence password = "!newPass1234";
        final String encodedWith_iso8859_1 = "{SSHA512}Fr4BnihVzVb0tqoknqjM1nP6K2fQ1deINvbqXmo8h8362k6Gmh7Av+KP68g9Llua6meqXVIXMP9CZvDd4sy1VlqZBQzLVgqF";
        final SSHA512PasswordEncoder passwordEncoder = new SSHA512PasswordEncoder("{SSHA512}",8, StandardCharsets.ISO_8859_1);
        Assertions.assertTrue(passwordEncoder.matches(password, encodedWith_iso8859_1));
    }

    @Test
    void utf8_ufsafe_ssha512_encoded_passwords_should_match() {
        final CharSequence password = "!newPass1234";
        final String encoded_with_utf8_and_ufSafe = "{SSHA512}MdMnk2tj2NuijXkjfTzFQicbxG-7SQ9Etzxqso6TzlorFm5g5kB_KKQZg694gQEnJvdPgkKrg1wxCzqXcQqZ_lqZBQzLVgqF";
        final SSHA512PasswordEncoder passwordEncoder = new SSHA512PasswordEncoder("{SSHA512}",8, StandardCharsets.UTF_8, true, false);
        Assertions.assertTrue(passwordEncoder.matches(password, encoded_with_utf8_and_ufSafe));
    }
}
