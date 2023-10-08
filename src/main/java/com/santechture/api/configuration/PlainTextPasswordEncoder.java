package com.santechture.api.configuration;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PlainTextPasswordEncoder implements PasswordEncoder {
 
    @Override
    public String encode(CharSequence rawPassword) {
        return rawPassword.toString();
    }
 
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return rawPassword.toString().equals(encodedPassword);
    }
 
    public static PasswordEncoder getInstance() {
        return INSTANCE;
    }
 
    private static final PasswordEncoder INSTANCE = new PlainTextPasswordEncoder();
 
    private PlainTextPasswordEncoder() {
    }  
}