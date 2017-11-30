package com.example.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;

@SpringBootApplication
public class SecurityApplication {

    @RestController
    public static class MyRestcontroller {

        @GetMapping("/hi")
        String hi() {
            SecurityContext context = SecurityContextHolder.getContext();
            Authentication authentication = context.getAuthentication();
            String name = authentication.getName();
            return "Hello, " + name;
        }
    }

    @Component
    public static class MySecurityConfig extends WebSecurityConfigurerAdapter {

        private final XAuthTokenConfigurer configurer;

        public MySecurityConfig(XAuthTokenConfigurer configurer) {
            this.configurer = configurer;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().authenticated();
            http.apply(this.configurer);
        }
    }

    @Component
    public static class XAuthTokenConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            MyCustomAuthFilter customFilter = new MyCustomAuthFilter();
            http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
        }

    }


    public static class MyCustomAuthFilter implements Filter {

        private Log log = LogFactory.getLog(getClass());

        @Override
        public void init(FilterConfig filterConfig) throws ServletException {
        }

        @Override
        public void doFilter(ServletRequest nonHttpRequest, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            HttpServletRequest servletRequest = HttpServletRequest.class.cast(nonHttpRequest);
            String auth = String.class.cast(servletRequest.getHeader("Authorization"));
            log.info("auth: " + auth);
            if (auth.contains("abc")) {
                log.info("token found!");
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(auth, "user",
                        Collections.singleton(new SimpleGrantedAuthority("ADMIN")));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            chain.doFilter(nonHttpRequest, response);
        }

        @Override
        public void destroy() {
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }
}
