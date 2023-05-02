package io.security.basicsecurirty.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfigSessionManage {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER") // hasRole을 사용하면 ROLE_ prefix가 붙는다
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // Spring EL 표현식이 사용이 가능하다.
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .successHandler(((request, response, authentication) ->  { // 인증 성공시 정보를 등록한다.
                    RequestCache requestCache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = requestCache.getRequest(request, response); // 사용자가 가고자 했던 요청 정보가 저장되어있다.
                    String redirectUrl = savedRequest.getRedirectUrl(); // 인증이 성공한 다음에 이동하려고 했던 페이지로 바로 이동할 수 있도록 처리
                    response.sendRedirect(redirectUrl);
                }));


        http
                .sessionManagement() // 최대 세션을 관리하는 인증 API
                .sessionFixation().changeSessionId() // 작성하지 않아도 Spring Security에서는 기본 셋팅이 되어있다 -> 세션 고정 공격을 방지한 세션 고정 보호기능이 동작
                .maximumSessions(1) // 한 계정으로 접속 가능한 최대 세션 개수
                .maxSessionsPreventsLogin(false); // 최대 세션 개수가 초과 되었을때 로그인이 되지 않는 전략(true: 인증 실패 전략, false: 세션 만료 전략) -> default = false

        http
                .sessionManagement() // 세션 정책을 정할 수 있다. 총 4가지가 있다(Always, If_Required, Never, Stateless) -> Never: 세션을 사용하지 않는 것이 아니라는 것에 주의
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

        http
                .exceptionHandling() // 예외처리 기능이 작동한다.
                .authenticationEntryPoint(((request, response, authException) -> { // 인증 예외 발생시 후속 처리 로직을 넣을 수 있다.
                    response.sendRedirect("/login"); // Spring Security에서 제공하는 페이지가 아닌 직접 만든 컨트롤러로 이동이 된다.
                }))
                .accessDeniedHandler(((request, response, accessDeniedException) -> { // 인가 예외 발생시 후속 처리 로직을 넣을 수 있다.
                    response.sendRedirect("/denied"); // Spring Security에서 제공하는 페이지가 아닌 직접 만든 컨트롤러로 이동이 된다.
                }));


        return http.build();
    }

    /*
    *  In-Memory User 등록 방법 -> WebSecurityConfigurerAdapter는 Deprecated 되었으므로 수정
    * */
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS", "USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER")
                .build();

        return new InMemoryUserDetailsManager(user, sys, admin);
    }
}
