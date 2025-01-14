package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthAdminRequest {
    @NotBlank(message = "email field is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "password field is required")
    private String password;
}
