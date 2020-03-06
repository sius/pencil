package io.liquer.spring.security.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
@ConditionalOnProperty(
    value="liquer.pencil.enabled",
    havingValue = "true",
    matchIfMissing = true)
public class PasswordEncoderAutoConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return DefaultPasswordEncoderFactories.passwordEncoder();
    }
}
