package com.portal.internship.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 1. Password Encoder bean to encrypt credentials safely using BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 2. Security Filter Chain to manage endpoint access and allow Postman testing
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF protection so Postman can send POST requests without security tokens
                .csrf(csrf -> csrf.disable())

                // Set permissions for your application endpoints
                .authorizeHttpRequests(auth -> auth
                        // Allow anyone to access the registration pages and static CSS styling assets
                        .requestMatchers("/auth/**", "/login", "/css/**", "/js/**").permitAll()
                        // Any other page in the future will require the user to log in first
                        .anyRequest().authenticated()
                )

                // Configure form login to use your custom registration route for testing handoffs
                .formLogin(form -> form
                        .loginPage("/auth/register")
                        .permitAll()
                );

        return http.build();
    }
}
