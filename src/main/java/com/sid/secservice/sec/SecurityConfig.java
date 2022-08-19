package com.sid.secservice.sec;

import com.sid.secservice.sec.filters.JwtAuthenticationFilter;
import com.sid.secservice.sec.filters.JwtAuthorizationFilter;
import com.sid.secservice.sec.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Autowired
//    private AccountService accountService;

    private UserDetailsServiceImpl  userDetailsService;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      // here we specify who are the users that have the rule to access

//         auth.userDetailsService(new UserDetailsService() {   // when a user authenticate use this methode to search this user from a service layer that  i created
//             @Override
//             public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {          //when the user enters their username & pw call this method
//                 AppUser appUser = accountService.loadUserByUsername(username);
//                 Collection<GrantedAuthority> authorities = new ArrayList<>();
//                 appUser.getAppRoles().forEach(appRole -> {
//                     authorities.add(new SimpleGrantedAuthority(appRole.getRoleName()));
//                 });
//
//                 return new User(appUser.getUsername(), appUser.getPassword(), authorities);  //user(username, pw, roles(collection<GrantedAuthority>) )
//             }
//         });

        auth.userDetailsService(userDetailsService);



    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // here we specify the rules of access
        http.csrf().disable(); // so if the forms are generated from the server (like the jsp file) so we need to protect them from csrf by using generate the synchronizer token.
                                // but if the form are generated in the client side with react or angular we need to disable the csrf, and we don't need to generate the synchronizer token and store it in the session.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // we will not use session in server side, we will manage  that using jwt. and the http.fromLogin() will not work bcz we don't generate session id
        //http.formLogin(); // for the login form // we should disable that becz we are using session STATELESS.
        http.headers().frameOptions().disable();//disable the protection for the frames. H2 console uses the frames, which are using also the csrf, so spring security hide its content util you authenticate
        //http.authorizeRequests().anyRequest().permitAll(); // here we authorize all the requests to have the access to all the functionalities. don't need authentication.
        http.authorizeRequests().antMatchers("/h2-console/**", "/refreshToken/**","login/**").permitAll(); // permit requests from /h2-console/**
        //http.authorizeRequests().antMatchers(HttpMethod.POST, "/users/**").hasAuthority("ADMIN"); // to add new user you need to be admin
        //http.authorizeRequests().antMatchers(HttpMethod.GET, "/users/**").hasAuthority("USER");
        http.authorizeRequests().anyRequest().authenticated(); // we need to authenticate to access to resources.
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {  // in the context we have an object of type AuthenticationManager and we can inject it where we want
        return super.authenticationManagerBean();
    }
}
