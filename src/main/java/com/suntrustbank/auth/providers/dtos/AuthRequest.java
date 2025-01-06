package com.suntrustbank.auth.providers.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthRequest {
    @Email(message = "Invalid email format")
    private String email;

    @Pattern(regexp = "\\d{10}", message = "phoneNumber field must be exactly 10 digits")
    private String phoneNumber;

    @NotBlank(message = "pin field is required")
    private String pin;

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private String userId;
}
