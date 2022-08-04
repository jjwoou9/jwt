package com.even.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    //시큐리티 등록 전에 실행
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("Filter 3");
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        //토큰 생성해줘야함. id,pw 정상적으로 들어와서 로그인이 완료되면 토큰 생성후 응답
        //요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 오고
        //그떄 토큰이 넘어오면 검증하면됨 (RSA, HS256)
        if(req.getMethod().equals("POST")){
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth " + headerAuth);

            if(headerAuth.equals("cors")){
                chain.doFilter(request, response);
            }else{
                PrintWriter out = res.getWriter();
                out.println("인증 안됨됨");
            }
        }



    }
}
