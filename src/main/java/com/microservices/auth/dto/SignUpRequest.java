package com.microservices.auth.dto;

import java.util.Set;

import lombok.Data;

@Data
public class SignUpRequest {
    private String username;
    private String email;
    private String password;
    private String phone;
    private Set<String> role;
    private String bankCode;
    private String flexFld1;
    private String flexFld2;

    // Constructors
    public SignUpRequest() {
    }

    public SignUpRequest(String username, String email, String password, String phone, Set<String> role) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.phone = phone;
        this.role = role;
    }

}
