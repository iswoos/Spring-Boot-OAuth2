package com.example.oauth2.config;

import com.example.oauth2.auth.MyAccessDeniedHandler;
import com.example.oauth2.auth.MyAuthenticationEntryPoint;
import com.example.oauth2.auth.oauth.PrincipalOauth2UserService;
import com.example.oauth2.domain.UserRole;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;


/**
 * Form Login에 사용하는 Security Config
 */
/* Security Config2(Jwt Token Login에서 사용)와 같이 사용하면 에러 발생
Security Form Login 진행하기 위해서는 이 부분 주석 제거 후 Security Config2에 주석 추가*/
@Configuration
@EnableWebSecurity

/* 다른 인증, 인가 방식 적용을 위한 어노테이션
@EnableGlobalMethodSecurity(prePostEnabled = true)
*/
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/security-login/info").authenticated()
                        .requestMatchers("/security-login/admin/**").hasAuthority(UserRole.ADMIN.name())
                        .anyRequest().permitAll()
                )
                .formLogin(formLogin -> formLogin
                        .loginPage("/security-login/login")
                        .defaultSuccessUrl("/security-login")
                        .failureUrl("/security-login/login")
                        .usernameParameter("loginId")
                        .passwordParameter("password")
                )
                .logout(logout -> logout
                        .logoutUrl("/security-login/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/security-login/login")
                        .defaultSuccessUrl("/security-login")
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(principalOauth2UserService)
                        )
                );

        http
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                        .accessDeniedHandler(new MyAccessDeniedHandler())
                );

        return http.build();
    }
}
