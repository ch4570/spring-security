package io.security.basicsecurirty.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfigSessionManage {

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                .formLogin();

        http
                .sessionManagement() // 최대 세션을 관리하는 인증 API
                .sessionFixation().changeSessionId() // 작성하지 않아도 Spring Security에서는 기본 셋팅이 되어있다 -> 세션 고정 공격을 방지한 세션 고정 보호기능이 동작
                .maximumSessions(1) // 한 계정으로 접속 가능한 최대 세션 개수
                .maxSessionsPreventsLogin(false); // 최대 세션 개수가 초과 되었을때 로그인이 되지 않는 전략(true: 인증 실패 전략, false: 세션 만료 전략) -> default = false

        http
                .sessionManagement() // 세션 정책을 정할 수 있다. 총 4가지가 있다(Always, If_Required, Never, Stateless) -> Never: 세션을 사용하지 않는 것이 아니라는 것에 주의
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);


        return http.build();
    }
}
