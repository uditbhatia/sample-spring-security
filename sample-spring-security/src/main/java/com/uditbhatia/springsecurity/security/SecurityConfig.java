package com.uditbhatia.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Spring Security Configuration CLass.
 * 
 * @author uditbhatia
 *
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@ComponentScan(basePackageClasses = UserDetailsService.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailService;
	
	/**
	 * Defines Application-Wide Configuration for the spring security.
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests()
				/**
				 * Exclude Pages That require public access.
				 */
				.antMatchers("/assets/**", "/templates/**", "/static/**",
						"/resources/**","/signup").permitAll().anyRequest()
				.authenticated().and()
				/**
				 * Form Login
				 */
				.formLogin()
				/**
				 * Login Page Url
				 */
				.loginPage("/login").permitAll()
				/**
				 * Default Success page
				 */
				.defaultSuccessUrl("/success").and()
				/**
				 * Remember-Me
				 */
				.rememberMe().key("remember_me").and()
				/**
				 * CSRF
				 */
				.csrf().disable()
				/**
				 * Log-out
				 */
				.logout().permitAll();

	}

	/**
	 * In this method we can give any custom UserDetailsService, Password Encoder e.t.c
	 * 
	 * @param auth
	 * @throws Exception
	 */
	@Autowired
	public void registerAuthentication(AuthenticationManagerBuilder auth)
			throws Exception {
		
		/**
		 * Our custom UserDetailsService or PasswordEncoder.
		 */
		auth.userDetailsService(userDetailService).passwordEncoder(
				new BCryptPasswordEncoder());
	}

}
