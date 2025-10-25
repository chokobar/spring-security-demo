package com.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    AuthenticationSuccessHandler roleBasedSuccessHandler() {
        return (request, response, authentication) -> {
            boolean isAdmin = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .anyMatch(auth -> auth.equals("ROLE_ADMIN"));

            response.sendRedirect(isAdmin ? "/admin" : "/home");
        };
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/home", "/auth/login", "/css/**", "/js/**", "/images/**").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()                     // 나머지는 로그인 필요
                )
                .formLogin(form -> form
                        .loginPage("/auth/login")      // GET 로그인 페이지
                        .loginProcessingUrl("/login")  // POST 인증 처리 URL
                        .successHandler(roleBasedSuccessHandler())
                        .failureUrl("/auth/login?error")
                        .permitAll()
                )
                .logout(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        // 학습용 계정 2개
        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin123") // 비밀번호 인코딩 없이 {noop}
                .roles("ADMIN")
                .build();

        UserDetails user = User.withUsername("user01")
                .password("{noop}user01")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }
}
