package com.mireHaskim.AuthService.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthServiceImpl implements AuthService{
    private final CognitoIdentityProviderClient cognitoIdentityProviderClient;
    private final String clientId = "7huntkavd8vqajj029vncb3hoj";
    private final String userPoolId = "us-east-1_5Cho9xmsC";

    public AuthServiceImpl(){
        this.cognitoIdentityProviderClient = CognitoIdentityProviderClient.builder()
                .region(Region.US_EAST_1)
                .build();
    }

    // 1️⃣ Sign Up User
    @Override
    public String signUp(String email, String password) {
        try {
            SignUpRequest request = SignUpRequest.builder()
                    .clientId(clientId)
                    .username(email)
                    .password(password)
                    .userAttributes(AttributeType.builder().name("email").value(email).build())
                    .build();

            cognitoIdentityProviderClient.signUp(request);

            AdminConfirmSignUpRequest confirmRequest = AdminConfirmSignUpRequest.builder()
                    .userPoolId(userPoolId)
                    .username(email)
                    .build();

            cognitoIdentityProviderClient.adminConfirmSignUp(confirmRequest);
            return "Signup successful! Please confirm your email.";
        } catch (CognitoIdentityProviderException e) {
            return "Signup failed: " + e.awsErrorDetails().errorMessage();
        }
    }

    // 2️⃣ Log In User
    @Override
    public Map<String, String> login(String email, String password) {
        try {
            InitiateAuthRequest request = InitiateAuthRequest.builder()
                    .clientId(clientId)
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .authParameters(Map.of(
                            "USERNAME", email,
                            "PASSWORD", password
                    ))
                    .build();

            InitiateAuthResponse response = cognitoIdentityProviderClient.initiateAuth(request);
            AuthenticationResultType result = response.authenticationResult();

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", result.accessToken());
            tokens.put("idToken", result.idToken());
            tokens.put("refreshToken", result.refreshToken());

            return tokens;
        } catch (CognitoIdentityProviderException e) {
            return Map.of("error", "Login failed: " + e.awsErrorDetails().errorMessage());
        }
    }

    // 3️⃣ Refresh Access Token
    @Override
    public Map<String, String> refreshAccessToken(String refreshToken) {
        try {
            InitiateAuthRequest request = InitiateAuthRequest.builder()
                    .clientId(clientId)
                    .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                    .authParameters(Map.of("REFRESH_TOKEN", refreshToken))
                    .build();

            InitiateAuthResponse response = cognitoIdentityProviderClient.initiateAuth(request);
            return Map.of("accessToken", response.authenticationResult().accessToken());
        } catch (CognitoIdentityProviderException e) {
            return Map.of("error", "Refresh failed: " + e.awsErrorDetails().errorMessage());
        }
    }

    // 4️⃣ Logout (Single Device)
    @Override
    public String logout(String accessToken) {
        try {
            RevokeTokenRequest request = RevokeTokenRequest.builder()
                    .clientId(clientId)
                    .token(accessToken)
                    .build();

            cognitoIdentityProviderClient.revokeToken(request);
            return "User logged out successfully.";
        } catch (CognitoIdentityProviderException e) {
            return "Logout failed: " + e.awsErrorDetails().errorMessage();
        }
    }

    // 5️⃣ Global Logout (All Devices)
    @Override
    public String globalLogout(String accessToken) {
        String username = extractUsernameFromToken(accessToken);

        try {
            AdminUserGlobalSignOutRequest request = AdminUserGlobalSignOutRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            cognitoIdentityProviderClient.adminUserGlobalSignOut(request);
            return "User logged out from all devices.";
        } catch (CognitoIdentityProviderException e) {
            return "Global logout failed: " + e.awsErrorDetails().errorMessage();
        }
    }

    // Helper Method: Extract Username from JWT Token
    private String extractUsernameFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getDecoder().decode(parts[1]));
            return new ObjectMapper().readValue(payload, Map.class).get("username").toString();
        } catch (Exception e) {
            return null;
        }
    }

}
