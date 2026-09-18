package ecommerce.back.security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

        private final JwtAuthFilter jwtAuthFilter;

        public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
                this.jwtAuthFilter = jwtAuthFilter;
        }

        // ============================================================
        // PASSWORD ENCODER
        // ============================================================

        @Bean
        public BCryptPasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        // ============================================================
        // SECURITY FILTER CHAIN
        // ============================================================

        @Bean
        public SecurityFilterChain securityFilterChain(
                        HttpSecurity http) throws Exception {

                http

                                // Disable CSRF because we are using JWT
                                .csrf(csrf -> csrf.disable())

                                // Enable CORS for React frontend
                                .cors(cors -> cors
                                                .configurationSource(corsConfigurationSource()))

                                // JWT is stateless
                                .sessionManagement(session -> session.sessionCreationPolicy(
                                                SessionCreationPolicy.STATELESS))

                                // =================================================
                                // AUTHORIZATION RULES
                                // =================================================
                                .authorizeHttpRequests(auth -> auth

                                                // -------------------------------
                                                // PUBLIC APIs
                                                // -------------------------------

                                                .requestMatchers(
                                                                "/freshers/signup",
                                                                "/freshers/login")
                                                .permitAll()

                                                // Anyone can see products/categories
                                                .requestMatchers(
                                                                "/products/**",
                                                                "/categories/**")
                                                .permitAll()

                                                // -------------------------------
                                                // ADMIN ONLY
                                                // -------------------------------

                                                // Only ROLE_ADMIN can access /admin/**
                                                .requestMatchers("/admin/**")
                                                .hasRole("ADMIN")

                                                // -------------------------------
                                                // EVERYTHING ELSE
                                                // -------------------------------

                                                .anyRequest()
                                                .authenticated())

                                // Disable default Spring login
                                .formLogin(form -> form.disable())

                                // Disable HTTP Basic
                                .httpBasic(basic -> basic.disable())

                                // Add our JWT filter
                                .addFilterBefore(
                                                jwtAuthFilter,
                                                UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }

        // ============================================================
        // CORS CONFIGURATION
        // ============================================================

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {

                CorsConfiguration configuration = new CorsConfiguration();

                // React frontend
                configuration.setAllowedOrigins(
                                List.of("http://localhost:5173"));

                // Allowed HTTP methods
                configuration.setAllowedMethods(
                                List.of(
                                                "GET",
                                                "POST",
                                                "PUT",
                                                "DELETE",
                                                "OPTIONS"));

                // Allow JWT Authorization header
                configuration.setAllowedHeaders(
                                List.of("*"));

                // Allow credentials
                configuration.setAllowCredentials(true);

                // Apply configuration to all endpoints
                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

                source.registerCorsConfiguration(
                                "/**",
                                configuration);

                return source;
        }
}