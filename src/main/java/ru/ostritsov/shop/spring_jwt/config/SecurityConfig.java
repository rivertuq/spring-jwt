package ru.ostritsov.shop.spring_jwt.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.ostritsov.shop.spring_jwt.filter.JwtAuthenticationFilter;
import ru.ostritsov.shop.spring_jwt.service.UserDetailsServiceImp;


@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final UserDetailsServiceImp userDetailsServiceImp;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    private final CustomAccessDeniedHandler accessDeniedHandler;

    private final CustomLogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        req -> req.requestMatchers("/login/**", "/register/**", "/refresh_token/**")
                                .permitAll()
                                .requestMatchers("/admin_only/**").hasAuthority("ADMIN")
                                .anyRequest()
                                .authenticated()
                ).userDetailsService(userDetailsServiceImp)
                .exceptionHandling(e -> e.accessDeniedHandler(accessDeniedHandler)
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(l -> l.logoutUrl("/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler(
                                ((request, response, authentication) -> SecurityContextHolder.clearContext())
                        ))
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
