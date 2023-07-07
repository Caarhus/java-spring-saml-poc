package com.example.demo;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {

    private Saml2AuthenticatedPrincipal principal = null;
	private List<String> groups = null;
	private Set<GrantedAuthority> authorities = new HashSet<>();

    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {

        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());

        http.authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated())
            .saml2Login(saml2 -> saml2
                .authenticationManager(new ProviderManager(authenticationProvider)))
            .saml2Logout(withDefaults());

        return http.build();
    }

    // private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {

    //     Converter<ResponseToken, Saml2Authentication> delegate =
    //         OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

    //     return (responseToken) -> {
    //         Saml2Authentication authentication = delegate.convert(responseToken);
    //         principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
    //         if (principal != null) {
    //             System.out.println("--------Chioke: principal: " + principal + "---------");
    //             groups = principal.getAttribute("groups");
    //         }
    //         authorities = new HashSet<>();

    //         if (groups != null) {
    //             groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
    //         } else {
    //             // if groups is not preset, try Auth0 attribute name
    //             groups = principal.getAttribute("http://schemas.auth0.com/roles");
    //             authorities.addAll(authentication.getAuthorities());
    //         }
    //         return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
    //     };
    // }

    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {
		System.out.println("--------Chioke: beginning of groupsConverter---------");
        Converter<ResponseToken, Saml2Authentication> delegate =
            OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();
		
		System.out.println("--------Chioke: delegate created---------");

		// Getting the token from the SAML response.
		Converter<ResponseToken, Saml2Authentication> returnToken;
		returnToken = (responseToken) -> {
            Saml2Authentication authentication = delegate.convert(responseToken);
			
			if(authentication != null) {
				System.out.println("--------Chioke: authentication: " + authentication + "---------");
				principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
				if (principal != null) {
					System.out.println("--------Chioke: principal: " + principal + "---------");
					groups = principal.getAttribute("groups");
				}
				authorities = new HashSet<>();

				if (groups != null) {
					groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
				} else {
					// if groups is not preset, try Auth0 attribute name
					groups = principal.getAttribute("http://schemas.auth0.com/roles");
					// groups = principal.getAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups");
					// groups = principal.getAttribute("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups");
					authorities.addAll(authentication.getAuthorities());
				}
				if (authorities != null) System.out.println("--------Chioke: authorities: " + authorities.toString() + "---------");
				return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
			}
			System.out.println("--------Chioke: authentication was null?---------");
            return new Saml2Authentication(null, null, null);
        };
        if (principal != null) System.out.println("--------Chioke: principal found: " + principal.toString() + "---------");
		if (groups != null) System.out.println("--------Chioke: groups found: " + groups.toString() + "---------");
		System.out.println("--------Chioke: returnToken created: " + returnToken.toString() + "---------");

		System.out.println("--------Chioke: end of groupsConverter---------");
		return returnToken;
    }
}
