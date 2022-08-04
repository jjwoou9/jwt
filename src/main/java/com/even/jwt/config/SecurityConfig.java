package com.even.jwt.config;

import com.even.jwt.config.jwt.JwtAUthenticationFilter;
import com.even.jwt.filter.MyFilter1;
import com.even.jwt.filter.MyFilter3;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CorsConfig corsConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter3(), UsernamePasswordAuthenticationFilter .class); //BeforeFilter BasicAuthenticFilter 실행전에 실행할 Filter 설정
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy((SessionCreationPolicy.STATELESS))//기본적으로 web은 stateless인데 statefull처럼 사용하기위해 세션과, 쿠키를 쓰는데 그방식을 쓰지 않겠다고 설정
                .and()
                .addFilter(corsConfig.corsFilter()) //CrossOrigin(인증x)
                .formLogin().disable() //form태그 로그인 안할거
                .httpBasic().disable() //authorization 사용시 header에 id,pw 담아서 사용하는게 httpBasic 방식. (이 방식 사용시 id pw 암호화가 안되서 https를 써야 암호화 할수 있음)
                .addFilter(new JwtAUthenticationFilter(authenticationManager())) //AuthenticationManager
                .authorizeRequests()
                .antMatchers("/api/v1/user/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
                .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_ADMIN') and hasRole('ROLE_USER')")
                .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

        super.configure(http);
    }
}
