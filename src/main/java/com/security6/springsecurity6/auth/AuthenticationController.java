package com.security6.springsecurity6.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public AuthenticationResponse register(@RequestBody RegisterRequest request){
        log.info("Registering user {}", request);
        return authenticationService.register(request);
    }

    @PostMapping("/authenticated")
    @ResponseStatus(HttpStatus.OK)
    public AuthenticationResponse register(@RequestBody AuthenticationRequest request){
        log.info("Authenticating user {}", request);
        return authenticationService.authenticate(request);
    }
}
