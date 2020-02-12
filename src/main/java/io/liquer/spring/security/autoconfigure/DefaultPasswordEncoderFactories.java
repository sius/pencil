package io.liquer.spring.security.autoconfigure;

import io.liquer.spring.security.encoder.SSHA224PasswordEncoder;
import io.liquer.spring.security.encoder.SSHA256PasswordEncoder;
import io.liquer.spring.security.encoder.SSHA384PasswordEncoder;
import io.liquer.spring.security.encoder.SSHA512PasswordEncoder;
import io.liquer.spring.security.encoder.SSHAPasswordEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class DefaultPasswordEncoderFactories {

    /**
     * deprecated PasswordEncoders removed
     * encoders.put("noop", NoOpPasswordEncoder.getInstance());
     * encoders.put("MD4", new Md4PasswordEncoder());
     * encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
     * encoders.put("SHA1", new MessageDigestPasswordEncoder("SHA-1"));
     * encoders.put("SHA-1", new MessageDigestPasswordEncoder("SHA-1"));
     * encoders.put("SHA-256", new MessageDigestPasswordEncoder("SHA-256"));
     * encoders.put("SHA256", new StandardPasswordEncoder());
     * LdapShaPasswordEncoder has been replaced by SSHAPasswordEncoder
     *
     * @return the DelegationPasswordEncoder
     */
    @Bean
    public static PasswordEncoder passwordEncoder() {
        final String defaultEncodeId = "bcrypt";
        return passwordEncoder(defaultEncodeId);
    }

    static PasswordEncoder passwordEncoder(String encodeId) {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();

        encoders.put("bcrypt", bcrypt);
        encoders.put("scrypt", new SCryptPasswordEncoder());
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());

        final PasswordEncoder ssha = new SSHAPasswordEncoder("", 8);
        encoders.put("ldap", ssha);
        encoders.put("SSHA", ssha);
        encoders.put("SSHA1", ssha);
        encoders.put("SSHA-1", ssha);

        final PasswordEncoder ssha224 = new SSHA224PasswordEncoder("", 8);
        encoders.put("SSHA224", ssha224);
        encoders.put("SSHA-224", ssha224);

        final PasswordEncoder ssha256 = new SSHA256PasswordEncoder("", 8);
        encoders.put("SSHA256", ssha256);
        encoders.put("SSHA-256", ssha256);

        final PasswordEncoder ssha384 = new SSHA384PasswordEncoder("", 8);
        encoders.put("SSHA384", ssha384);
        encoders.put("SSHA-384", ssha384);

        final PasswordEncoder ssha512 = new SSHA512PasswordEncoder("", 8);
        encoders.put("SSHA512", ssha512);
        encoders.put("SSHA-512", ssha512);

        final DelegatingPasswordEncoder ret = new DelegatingPasswordEncoder(encodeId, encoders);
        ret.setDefaultPasswordEncoderForMatches(bcrypt);
        return ret;
    }

}
