package com.example.demo.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.demo.security.ApplicationUserPermission.*;
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()// 200 status --post ,delete,put were working
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/**")
                .permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())

       /*         .antMatchers(HttpMethod.DELETE,"/managment/api/**")
                 .hasAuthority(Course_WRITE.getPermission())

                .antMatchers(HttpMethod.PUT,"/managment/api/**")
                .hasAuthority(Course_WRITE.getPermission())

                .antMatchers(HttpMethod.POST,"/managment/api/**")
                .hasAuthority(Course_WRITE.getPermission())

                .antMatchers(HttpMethod.GET,"/managment/api/**")
                .hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
*/
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annaSmith")
                .password(passwordEncoder.encode("password"))
               // .roles(ApplicationUserRole.STUDENT.name())//role student
                .authorities(STUDENT.getGrantedAuthority())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
               // .roles(ADMIN.name())//role admin
                .authorities(ADMIN.getGrantedAuthority())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password1234"))
              //  .roles(ADMINTRAINEE.name())//role adminTrainee
                .authorities(ADMINTRAINEE.getGrantedAuthority()) //TODO it has problem as it can not post,put and delete??
                .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser
                , lindaUser,
                tomUser);
    }
}
