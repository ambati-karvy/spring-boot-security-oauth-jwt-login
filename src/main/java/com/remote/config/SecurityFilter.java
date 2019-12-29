package com.remote.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;


public class SecurityFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
    	
    	/*RestTemplate restTemplate = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-Type", "application/x-www-form-urlencoded");
		headers.add("Authorization", "Basic c2FtcGxlQ2xpZW50SWQ6c2VjcmV0");

		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("username","user@user.com");
		map.add("password","password");
		map.add("grant_type","password");
		
		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);

		ResponseEntity<TokenResponseDto> response =
		    restTemplate.exchange("http://localhost:8080/oauth/token",
		                          HttpMethod.POST,
		                          entity,
		                          TokenResponseDto.class);*/
    	
        httpResponse.setHeader("Authorization", "abc");
        filterChain.doFilter(httpRequest, httpResponse);
    }
} 
