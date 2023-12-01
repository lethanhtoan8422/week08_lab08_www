package fit.se.week8.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.sql.DataSource;

import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    public void globalConfig(AuthenticationManagerBuilder auth, PasswordEncoder encoder, DataSource dataSource) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource)
                .withUser(User.withUsername("admin")
                        .password(encoder.encode("admin"))
                        .roles("ADMIN")
                        .build())
                .withUser(User.withUsername("teo")
                        .password(encoder.encode("teo"))
                        .roles("TEO")
                        .build())
                .withUser(User.withUsername("ty")
                        .password(encoder.encode("ty"))
                        .roles("USER")
                        .build())
        ;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/home", "/index","/login","/logout").permitAll()//nhung links nay
                        .requestMatchers("/api/**").hasAnyRole("ADMIN", "USER", "TEO")//nhung
                        .requestMatchers(("/admin/**")).hasRole("ADMIN")//uri bat dau bang
                        .requestMatchers("/api/v1/auth/**", "/v2/api-docs/**", "/v3/api-docs/**",
                                "/swagger-resources/**", "/swagger-ui/**", "/webjars/**").permitAll()
                        .anyRequest().authenticated()//cac uri khac can dang nhap duoi bat ky
                ).formLogin(withDefaults()
                )
                .logout(withDefaults()
                ).csrf(csrf->csrf.ignoringRequestMatchers("/h2-console/**")).headers(headers->headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .httpBasic(withDefaults());
        http.cors(corsConfigurer -> corsConfigurer.configurationSource(corsConfiguration()));
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfiguration() {
        return request -> {
            org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
            config.setAllowedHeaders(Collections.singletonList("*"));
            config.setAllowedMethods(Collections.singletonList("*"));
            config.setAllowedOriginPatterns(Collections.singletonList("*"));
            config.setAllowCredentials(true);
            return config;
        };
    }
}
