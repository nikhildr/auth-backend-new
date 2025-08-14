package com.microservices.auth.dto;

import com.microservices.auth.entity.BackOfficeUser;
import lombok.Data;

import java.util.Set;

@Data
public class JwtAuthenticationResponse {
    private String accessToken;
    private String tokenType = "Bearer";

    private BackOfficeUser user;
    private Set<String> uiPermissions;

    public JwtAuthenticationResponse(String accessToken) {
        this.accessToken = accessToken;
    }


}
