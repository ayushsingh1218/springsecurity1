package com.example5.Security6.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.example5.Security6.filter.JwtAuthenticationFilter;
import com.example5.Security6.service.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    

    @Autowired
    private JwtAuthenticationFilter jwtFilter;
    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;
  

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        
        return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(
                        req->req.requestMatchers("/login/**","/register/**")
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                    ).userDetailsService(userDetailsServiceImpl)
                    .sessionManagement(session->session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                        .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    
}
