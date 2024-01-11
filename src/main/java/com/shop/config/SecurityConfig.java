package com.shop.config;

import com.shop.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    MemberService memberService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorizeRequests) -> {
                            authorizeRequests
                                    .requestMatchers("/", "/members/**", "/item/**", "/images/**").permitAll()
                                    .requestMatchers("/css/**", "/js/**", "/img/**").permitAll()
                                    .requestMatchers("/admin/**").hasRole("ADMIN")
                                    .anyRequest().authenticated();
                })
                .exceptionHandling(exceptionHandling -> {
                    exceptionHandling
                            .authenticationEntryPoint(new CustomAuthenticationEntryPoint());
                })
                .formLogin((formLogin) -> {
                    formLogin
                            .loginPage("/members/login")
                            .defaultSuccessUrl("/")
                            .usernameParameter("email")
                            .failureUrl("/members/login/error");
                })
                .logout((logout) -> {
                    logout
                            .logoutUrl("/members/logout")
                            .logoutSuccessUrl("/");
                })
                .csrf((csrfConfig) -> {
                    csrfConfig.disable();
                });
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
