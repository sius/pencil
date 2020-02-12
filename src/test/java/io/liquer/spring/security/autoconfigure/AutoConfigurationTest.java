package io.liquer.spring.security.autoconfigure;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

public class AutoConfigurationTest {

    private final ApplicationContextRunner contextRunner =
        new ApplicationContextRunner().withConfiguration(
            AutoConfigurations.of(PasswordEncoderAutoConfiguration.class));

    @Test
    void passwordEncoderBean() {
        this.contextRunner.withUserConfiguration(MyConfiguration.class).run((context) -> {
            assertThat(context).hasSingleBean(PasswordEncoder.class);
            assertThat(context.getBean(PasswordEncoder.class))
                .isSameAs(context.getBean(MyConfiguration.class).passwordEncoder());
        });
    }

    @Configuration
    static class MyConfiguration {

        @Bean
        public PasswordEncoder passwordEncoder() {
            return DefaultPasswordEncoderFactories.passwordEncoder();
        }

    }
}
