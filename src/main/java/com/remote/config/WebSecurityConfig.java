package com.remote.config;


import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.remote.dto.TokenResponseDto;
import com.remote.model.User;
import com.remote.service.CustomUserDetailsService;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
/*import io.restassured.RestAssured;
import io.restassured.response.Response;*/

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService)
                .passwordEncoder(encoder());
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http//.cors().and()
        // .addFilterBefore(customCorsFilter(), SessionManagementFilter.class)
        .authorizeRequests().antMatchers("/login").permitAll()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .permitAll()
                .anyRequest().authenticated()
                .and().formLogin()
                .loginPage("/login")
                .successHandler(successHandler())
                .failureHandler(failureHandler())
                .permitAll()
                .and().csrf().disable()
                .logout().permitAll();
    }
    
    /*CorsFilter1 customCorsFilter() {
    	CorsFilter1 filter = new CorsFilter1();
        return filter;
    }*/
    
    /*@Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addExposedHeader("Authorization, authorization, x-xsrf-token, Access-Control-Allow-Headers, Origin, Accept, X-Requested-With, " +
                "Content-Type, Access-Control-Request-Method, Custom-Filter-Header");
        config.addAllowedHeader("*");
        config.addAllowedMethod("OPTIONS");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("DELETE");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }*/
    
    //@Autowired DefaultTokenServices tokenServices;
    //@Autowired TokenEnhancer tokenEnhancer;
    
    //@Autowired OAuth2AuthorizedClientService clientService;
    OAuth2AuthorizedClientService clientService;
    private AuthenticationSuccessHandler successHandler() {
        return new AuthenticationSuccessHandler() {
          @Override
          public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        
        	HttpSession session = httpServletRequest.getSession();
      		
      		/*Set some session variables*/
      		User authUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();  
            session.setAttribute("uname", authUser.getUsername());  
            session.setAttribute("authorities", authentication.getAuthorities());
            
            final Map<String, Object> additionalInfo = new HashMap<>();
            
            additionalInfo.put("user_id", authUser.getId());
            //additionalInfo.put("business_id", authUser.getBusinessId());
        	
            
            
            /*Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication1;
            String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
            OAuth2AuthorizedClient client =
                    clientService.loadAuthorizedClient(clientRegistrationId, oauthToken.getName());
                String accessToken = client.getAccessToken().getTokenValue();*/
            
            /*Map<String, String> params = new HashMap<String, String>();
            params.put("grant_type", "password");
            params.put("client_id", "sampleClientId");
            params.put("username", "user@user.com");
            params.put("password", "password");
            
            
            Response response = RestAssured.given().auth().preemptive()
              .basic("sampleClientId", "secret").and().with().params(params).when()
              .post("http://localhost:8080/oauth/token");
            
            String token = response.jsonPath().getString("access_token");*/
            
            
            
            //OAuth2Authentication auth = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            
            //System.out.println("-----"+accessToken);
            
            RestTemplate restTemplate = new RestTemplate();

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
			                          TokenResponseDto.class);
			
			//System.out.println("-----"+response.getBody().getAccess_token());
			
			Cookie cookie = new Cookie("Token", response.getBody().getAccess_token());
           
			System.out.println("authanticated");
            
            httpServletResponse.addHeader("Authorization", "Bearer "+response.getBody().getAccess_token());
            httpServletResponse.addCookie(cookie);
            httpServletResponse.setContentType("application/json");
        	httpServletResponse.getWriter().append("{message:Your SSN was registered successfully., status: 200}");
            httpServletResponse.setStatus(200);
          }
        };
    }
    
    private AuthenticationFailureHandler failureHandler() {
        return new AuthenticationFailureHandler() {
          @Override
          public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
            httpServletResponse.getWriter().append("Authentication failure");
            httpServletResponse.setStatus(401);
          }
        };
    }
    
   
    
    
   /* @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/login").permitAll()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .permitAll()
                .anyRequest().authenticated()
                .and().formLogin()
                .loginPage("/login")
                .successHandler(successHandler())
                .failureHandler(failureHandler())
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                .authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .csrf().csrfTokenRepository(csrfTokenRepository()).and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);
    }
    
    private AuthenticationSuccessHandler successHandler() {
        return new AuthenticationSuccessHandler() {
          @Override
          public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
            httpServletResponse.getWriter().append("OK");
            httpServletResponse.setStatus(200);
          }
        };
    }
    
    private AuthenticationFailureHandler failureHandler() {
        return new AuthenticationFailureHandler() {
          @Override
          public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
            httpServletResponse.getWriter().append("Authentication failure");
            httpServletResponse.setStatus(401);
          }
        };
    }
    
    private AccessDeniedHandler accessDeniedHandler() {
        return new AccessDeniedHandler() {
          @Override
          public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
            httpServletResponse.getWriter().append("Access denied");
            httpServletResponse.setStatus(403);
          }
        };
      }

      private AuthenticationEntryPoint authenticationEntryPoint() {
        return new AuthenticationEntryPoint() {
          @Override
          public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
            httpServletResponse.getWriter().append("Not authenticated");
            httpServletResponse.setStatus(401);
          }
        };
      }

      private Filter csrfHeaderFilter() {
        return new OncePerRequestFilter() {
          @Override
          protected void doFilterInternal(HttpServletRequest request,
                                          HttpServletResponse response, FilterChain filterChain)
              throws ServletException, IOException {
            CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class
                .getName());
            if (csrf != null) {
              Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
              String token = csrf.getToken();
              if (cookie == null || token != null
                  && !token.equals(cookie.getValue())) {
                cookie = new Cookie("XSRF-TOKEN", token);
                cookie.setPath("/");
                response.addCookie(cookie);
              }
            }
            filterChain.doFilter(request, response);
          }
        };
      }

      private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
      }*/
    
    

}
