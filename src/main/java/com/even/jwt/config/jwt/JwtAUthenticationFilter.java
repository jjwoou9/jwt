package com.even.jwt.config.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// /login 요청하면 username, password post전송시
// UsernamePasswordAuthenticationFilter동작함.
// securityConfig에서 formLogin을 disable해놔서 다시 addFilter해야됨.
public class JwtAUthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JwtAUthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticaiton 로그인 시도중");
        
        
        /*
        1. username, passworod 받아서
        
        2. 정상인지 로그인 시도. authenticationManager로 로그인 시도를 하면 PrincipalDetailsservice를 실행
         -> 그럼 loadUserbyUserName()실행

         3. PrincipalDetails를 세션에 담고
            -세션에 답는 이유는 security에서 권한관리를 하기위해서
            -별도의 권한관리 없으면 session에 담을 필요 x



         4. JWT 토큰을 만들어서 응답.
         */
        return super.attemptAuthentication(request, response);
    }
}
