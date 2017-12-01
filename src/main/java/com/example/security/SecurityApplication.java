package com.example.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@SpringBootApplication
public class SecurityApplication {

    @RestController
    static class GreetingsRestController {

        @GetMapping("/hi")
        String hi(@AuthenticationPrincipal String name) {
            return "Hello, " + name;
        }
    }

    @Component
    static class MySecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().authenticated();
            http.addFilterBefore(new MyCustomAuthFilter(), UsernamePasswordAuthenticationFilter.class);
        }
    }

    private static class MyCustomAuthFilter implements Filter {

        private Log log = LogFactory.getLog(getClass());

        @Override
        public void init(FilterConfig filterConfig) throws ServletException {
        }

        @Override
        public void doFilter(ServletRequest nonHttpRequest, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            String auth = String.class.cast(
                    HttpServletRequest.class.cast(nonHttpRequest).getHeader(HttpHeaders.AUTHORIZATION));
            log.info("auth: " + auth);
            if (auth.contains("abc")) {
                log.info("token found!");
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("user", "pw",
                        AuthorityUtils.createAuthorityList("ADMIN"));
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
