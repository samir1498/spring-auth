package com.samir.springauth.controllers;

import com.samir.springauth.requests.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final HttpSessionSecurityContextRepository httpSessionSecurityContextRepository;

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest LoginRequest,
                        HttpServletRequest request,
                        HttpServletResponse response){
        try {
            UsernamePasswordAuthenticationToken authenticationRequest =
                    new UsernamePasswordAuthenticationToken(
                            LoginRequest.getUsername(), LoginRequest.getPassword());

            Authentication authentication = authenticationManager.authenticate(authenticationRequest);

            // Create a SecurityContext and set the Authentication in it
            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authentication);

            // Save the SecurityContext in the HttpSession
            httpSessionSecurityContextRepository.saveContext(context, request, response);

            return "login success";
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
