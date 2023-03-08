package com.zinzza.springsecuritypractice.config;

import com.zinzza.springsecuritypractice.jwt.JwtAuthenticationFilter;
import com.zinzza.springsecuritypractice.jwt.JwtAuthorizationFilter;
import com.zinzza.springsecuritypractice.jwt.JwtProperties;
import com.zinzza.springsecuritypractice.user.User;
import com.zinzza.springsecuritypractice.user.UserRepository;
import com.zinzza.springsecuritypractice.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Security 설정 Config
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserService userService;
    private final UserRepository userRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable(); // basic authentication filter 비활성화
        http.csrf().disable(); // csrf
        http.rememberMe().disable(); // remember me
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션 사용 x

        http.addFilterBefore(
                new JwtAuthenticationFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class
        ).addFilterBefore(
                new JwtAuthorizationFilter(userRepository),
                BasicAuthenticationFilter.class
        );

        http.authorizeRequests() // authorization(인가 설정)
                // /, /home, /signup은 모두에게 허용
                .antMatchers("/", "/home", "/signup").permitAll()
                // note 페이지는 USER롤을 가진 유저에게만 허용
                .antMatchers("/note").hasRole("USER")
                // admin 페이지는 ADMIN롤을 가진 유저에게만 허용
                .antMatchers("/admin").hasRole("ADMIN")
                // ADMIN롤을 가진 유저만 post로 notice로 접근 허용
                .antMatchers(HttpMethod.POST, "/notice").hasRole("ADMIN")
                // ADMIN롤을 가진 유저만 delete로 notice로 접근 허용
                .antMatchers(HttpMethod.DELETE, "/notice").hasRole("ADMIN")
                .anyRequest().authenticated();

        http.formLogin() // 로그인 설정
                .loginPage("/login")
                .defaultSuccessUrl("/")
                .permitAll(); // 모두 허용

        http.logout() //로그아웃 설정
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .deleteCookies(JwtProperties.COOKIE_NAME);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 정적 리소스 spring security 대상에서 제외 web.ignoring().antMatchers("/images/**", "/css/**"); 아래 코드와 같은 내용
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /**
     * UserDetailsService 구현
     *
     * @return UserDetailsService
     */
    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        return username -> {
            User user = userService.findByUsername(username);
            if (user == null)
                throw new UsernameNotFoundException(username);

            return user;
        };
    }

}
