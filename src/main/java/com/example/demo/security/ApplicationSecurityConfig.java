package com.example.demo.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.server.Session;
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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

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
               // .csrf().disable()//version-1 200 status --post ,delete,put were working // version-2 it does not generate in postman???
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/**")
                .permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())

                //version-1 permission
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
                //.httpBasic();// version -1 basic oath
                .formLogin()
                .loginPage("/login").permitAll();
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
