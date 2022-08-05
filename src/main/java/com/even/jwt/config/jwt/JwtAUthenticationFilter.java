package com.even.jwt.config.jwt;

import com.even.jwt.config.auth.PrincipalDetails;
import com.even.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

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

        try {
            //form 요청 처리
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            {
//                while ((input = br.readLine()) != null) {
//                    System.out.println(input);
//                }
//            }


            //JSON 요청 처리
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(),User.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailsService의 loadUserByUsername()함수가 실행됨.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인? " + principalDetails.getUser().getUsername()); //값이 정상적으로 있으면 로그인이 정상적으로 되었다는ㄷ 뜻
            System.out.println("====================================");
            //authentication 객체가 session영역에 저장을 해야하고 그 방법이 return 해주면 됨
            //return의 이유는 권한 관리를 security가 대신 해주기 때문에 편리성을 위해서
            //굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 세션에 넣어줌

            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    //attemptAutnetication실행후 인증이 정상적으로 되었으면 succesulAuthentication 함수가 실햄됨
    //여기서 JWT 토큰을 만들어서 JWT토큰을 내려주면됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication ");
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
