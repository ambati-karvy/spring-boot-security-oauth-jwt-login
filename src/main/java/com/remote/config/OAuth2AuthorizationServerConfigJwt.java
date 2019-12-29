package com.remote.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;

import javax.sql.DataSource;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfigJwt extends AuthorizationServerConfigurerAdapter {

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Autowired
    ClientDetailsService clientDetailsService;

    @Autowired
    DataSource dataSource;

    @Value("${app.redirectUriList}")
    private String redirectUriList;

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer){
        oauthServer.tokenKeyAccess("permitAll()").allowFormAuthenticationForClients();
        oauthServer.passwordEncoder(noOpEncoder());
    }

    @Bean
    public PasswordEncoder noOpEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            .withClient("sampleClientId")
            .secret("secret")
            .redirectUris(redirectUriList.split(","))
            //.authorizedGrantTypes("implicit")
            .authorizedGrantTypes("implicit", "password", "refresh_token")
            .scopes("read", "write", "foo", "bar")
            .autoApprove(true)
            .accessTokenValiditySeconds(2500);
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        final DefaultTokenServices defaultTokenServices = new CustomTokenServices(tokenStore());
    	//DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setClientDetailsService(clientDetailsService);
        return defaultTokenServices;
    }
    
/* // Token services. Needed for JWT
 	@Bean
 	@Primary
 	public DefaultTokenServices tokenServices() {
 		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
 		defaultTokenServices.setTokenStore(tokenStore());
 		return defaultTokenServices;
 	}*/

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(
        	      Arrays.asList(tokenEnhancer(), accessTokenConverter()));
        
        endpoints.tokenStore(tokenStore())
        .tokenEnhancer(tokenEnhancerChain)
        .authenticationManager(authenticationManager);
        
       /* endpoints
		.tokenStore(tokenStore())
		.accessTokenConverter(accessTokenConverter()) // added for JWT
		.authenticationManager(authenticationManager);*/
    }
    
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new CustomTokenEnhancer();
    }

    /*@Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource);
    }*/
    
    @Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter()); // For JWT. Use in-memory, jdbc, or other if not JWT
	}

	// Token converter. Needed for JWT
	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setSigningKey("123"); // symmetric key
		return converter;
	}

}
