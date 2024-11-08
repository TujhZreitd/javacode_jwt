package javacode.jwtsecurity.filter;

import java.io.IOException;
import java.util.Collections;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


@Component
public class LoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        logger.info("Incoming request: {} {}", request.getMethod(), request.getRequestURI());

        Collections.list(request.getHeaderNames()).forEach(headerName -> {
            String headerValue = request.getHeader(headerName);
            logger.info("Header: {} = {}", headerName, headerValue);
        });

        request.getParameterMap().forEach((key, value) -> {
            logger.info("Parameter: {} = {}", key, String.join(",", value));
        });
        filterChain.doFilter(request, response);
        logger.info("Outgoing response status: {}", response.getStatus());
    }
}
