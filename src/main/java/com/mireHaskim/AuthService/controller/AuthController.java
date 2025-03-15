package com.mireHaskim.AuthService.controller;

import com.mireHaskim.AuthService.model.UserNameAndPassword;
import com.mireHaskim.AuthService.service.AuthService;
import com.mireHaskim.AuthService.service.AuthServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthServiceImpl authService;


    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody UserNameAndPassword userNameAndPassword){
        String response = authService.signUp(userNameAndPassword.getEmail(), userNameAndPassword.getPassword());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody UserNameAndPassword userNameAndPassword){
      Map<String, String> response =   authService.login(userNameAndPassword.getEmail(), userNameAndPassword.getPassword());
        return ResponseEntity.ok(response);
    }

    // 3️⃣ Refresh Token (Get New Access Token)
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody Map<String, String> requestBody) {
      Map<String, String> response = authService.refreshAccessToken(requestBody.get("refreshToken"));
            return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        String response = authService.logout(authHeader.substring(7));
        return ResponseEntity.ok(response);

    }


}
