package com.mireHaskim.AuthService.service;

import org.springframework.stereotype.Service;
import java.util.Map;

public interface AuthService {
    String signUp(String email, String password);
    Map<String, String> login(String email, String password);
    Map<String, String> refreshAccessToken(String refreshToken);
    String logout(String accessToken);
    String globalLogout(String accessToken);
}
