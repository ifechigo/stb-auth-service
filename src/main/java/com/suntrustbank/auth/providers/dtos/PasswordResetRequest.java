package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Generated;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Generated
public class PasswordResetRequest {
    @NotBlank(message = "Email address is required")
    @Email(message = "Invalid email format")
    private String email;
}
