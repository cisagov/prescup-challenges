package edu.cmu.sei.cert.prescup21.ecommerce.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import edu.cmu.sei.cert.prescup21.ecommerce.enumeration.State;
import edu.cmu.sei.cert.prescup21.ecommerce.filter.DifficultyFilter;
import edu.cmu.sei.cert.prescup21.ecommerce.util.GameState;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter
{
	
	@Autowired
	public void configureGlobal( AuthenticationManagerBuilder auth ) throws Exception
	{
		auth
		.inMemoryAuthentication()
		.withUser( "kowalski" ).password( passwordEncoder().encode( "tartans" ) ).roles( "USER" )
		.and()
		.withUser( "cortex" ).password( passwordEncoder().encode( "vortex" ) ).roles( "USER" )
		.and()
		.withUser( "admin" ).password( passwordEncoder().encode( "AncientMariner99" ) ).roles( "ADMIN" );
	}

	@Override
	protected void configure( HttpSecurity http ) throws Exception
	{
		http.csrf().ignoringAntMatchers( "/admin/**", "/rest/**" )
		    .and().authorizeRequests()
		    .antMatchers( "/admin/**" ).hasRole( "ADMIN" )
		    .antMatchers( "/" ).permitAll()
		    .antMatchers( "/css/**" ).permitAll()
		    .antMatchers( "/js/**" ).permitAll()
		    .anyRequest().authenticated()
		    .and()
		    .formLogin()
		    .and()
		    .addFilterAfter( new DifficultyFilter(), BasicAuthenticationFilter.class );
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}
	
}
