package com.microservices.auth.controller;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class test {


        public static void main(String[] args) {
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

            String rawPassword = "admin123"; // Change this to the password you want to encode
            String encodedPassword = passwordEncoder.encode(rawPassword);

            System.out.println("Raw password: " + rawPassword);
            System.out.println("Encoded password: " + encodedPassword);
        }
    }