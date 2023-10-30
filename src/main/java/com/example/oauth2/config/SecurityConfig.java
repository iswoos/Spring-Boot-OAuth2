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
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
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
