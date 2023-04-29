package io.security.basicsecurirty.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // -> 필수적으로 넣어야한다.
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http // 인가 API
                .authorizeRequests() // 요청에 대한 보안 검색이 한다.
                .anyRequest().authenticated(); // 어떠한 요청에도 인증을 해야한다.

        http // 인증 API
                .formLogin(); // 인증 방식은 formLogin으로 설정한다.

        return http.build();
    }

}
