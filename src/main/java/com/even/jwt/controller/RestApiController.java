package com.even.jwt.controller;

import com.even.jwt.config.auth.PrincipalDetails;
import com.even.jwt.model.User;
import com.even.jwt.repsoitory.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    UserRepository userRepository;

    @GetMapping("home")
    public String home(){
        return " <h1>home</h1>";
    }

    @PostMapping("token")
    public String token(){
        return " <h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }


    //user & manager & admin
    @GetMapping("api/v1/user")
    public String user() {

        return "<h1>user</h1>";
    }

    //manager & admin
    @GetMapping("api/v1/manager")
    public String manager() {

        return "<h1>manager</h1>";
    }

    //only admin
    @GetMapping("api/v1/admin")
    public String admin() {

        return "<h1>admin</h1>";
    }
}
