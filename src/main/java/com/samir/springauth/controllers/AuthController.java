package com.samir.springauth.controllers;

import com.samir.springauth.requests.LoginRequest;
import com.samir.springauth.utils.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    @PostMapping("/login")
    public String login(@RequestBody LoginRequest LoginRequest){
        try {
            UsernamePasswordAuthenticationToken authenticationRequest =
                    new UsernamePasswordAuthenticationToken(
                            LoginRequest.getUsername(), LoginRequest.getPassword());

            Authentication authentication = authenticationManager.authenticate(authenticationRequest);

            // Create a SecurityContext and set the Authentication in it
            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authentication);

            return jwtUtils.generateToken(LoginRequest.getUsername());
        } catch (AuthenticationException e) {
            return "Authentication failed";
        }
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            // Invalidate the HttpSession
            request.getSession().invalidate();

            // Clear the SecurityContext
            SecurityContextHolder.clearContext();

            return ResponseEntity.ok("logout success");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Logout failed");
        }
    }
}
