package io.liquer.spring.security.autoconfigure;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

public class AutoConfigurationWithConditionalPropertyTest {

    private final ApplicationContextRunner contextRunner =
        new ApplicationContextRunner()
            .withConfiguration(
                AutoConfigurations.of(PasswordEncoderAutoConfiguration.class));

    @Test
    void enabled_passwordEncoderBean_should_be_loaded() {
        this.contextRunner
            .withPropertyValues("liquer.pencil.enabled=true")
            .withUserConfiguration(MyConfiguration.class).run((context) -> {
                assertThat(context).hasSingleBean(PasswordEncoder.class);
                assertThat(context.getBean(PasswordEncoder.class))
                   .isSameAs(context.getBean(MyConfiguration.class).passwordEncoder);
        });
    }

    @Test
    void without_conditional_property_passwordEncoderBean_should_be_loaded() {
        this.contextRunner
                .withUserConfiguration(MyConfiguration.class).run((context) -> {
            assertThat(context).hasSingleBean(PasswordEncoder.class);
            assertThat(context.getBean(PasswordEncoder.class))
                    .isSameAs(context.getBean(MyConfiguration.class).passwordEncoder);
        });
    }

    @Test
    void disabled_passwordEncoderBean_should_not_be_loaded() {
        this.contextRunner
                .withPropertyValues("liquer.pencil.enabled=false")
                .withUserConfiguration(MyConfiguration.class).run((context) -> {
            assertThat(context).doesNotHaveBean(PasswordEncoder.class);
            assertThat(context.getBean(MyConfiguration.class).passwordEncoder).isNull();
        });
    }

    @Configuration
    static class MyConfiguration {

        @Autowired(required = false)
        private PasswordEncoder passwordEncoder;
    }
}
