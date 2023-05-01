package io.security.basicsecurirty.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

//@Configuration
//@EnableWebSecurity // -> 필수적으로 넣어야한다.
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http // 인가 API
                .authorizeRequests() // 요청에 대한 보안 검색이 한다.
                .anyRequest().authenticated(); // 어떠한 요청에도 인증을 해야한다.

        http // 인증 API - formLogin
                .formLogin() // 인증 방식은 formLogin으로 설정한다.
//                .loginPage("/loginPage") // 사용자 지정 로그인 페이지 사용이 가능하다.
                .defaultSuccessUrl("/") // 인증이 성공했을때 기본적으로 이동할 URL 설정이 가능하다.
                .failureUrl("/login") // 인증에 실패했을때 이동할 URL 설정
                .usernameParameter("userId") // form 태그의 기본 이름을 변경할 수 있다.
                .passwordParameter("passwd") // form 태그의 기본 이름을 변경할 수 있다.
                .loginProcessingUrl("/login_proc") // form 태그의 action URL을 설정
                .successHandler(new AuthenticationSuccessHandler() { // 인증 성공시 사용할 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication = " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { // 인증 실패시 사용할 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception = " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll();  // 모든 사용자는 `/loginPage` 에 인증없이 이동이 가능하다.

        http    // 인증 API - Logout
                .logout()
                .logoutUrl("/logout") // 로그아웃 URL 지정이 가능하고, 디폴트는 /logout 이다.
                .logoutSuccessUrl("/login") // 로그아웃 성공시 이동 URL
                .addLogoutHandler(((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();
                }))
                .logoutSuccessHandler(((request, response, authentication) -> {
                    response.sendRedirect("/login");
                }))
                .deleteCookies("remember-me"); // 삭제할 쿠키를 선언할 수 있다.

        http   // 인증 API - Remember Me 인증
                .rememberMe()
                .rememberMeParameter("remember") // 기본값은 remember-me
                .tokenValiditySeconds(3600) // 초단위로 지정할 수 있다. 기본값은 14일이다.
                .userDetailsService(userDetailsService);



        return http.build();
    }

}
