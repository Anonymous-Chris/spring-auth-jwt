package com.chris.springboot.microservices.springauth.auth;

import com.chris.springboot.microservices.springauth.dto.LoginDto;

public interface AuthService {
    String login(LoginDto loginDto);
}
