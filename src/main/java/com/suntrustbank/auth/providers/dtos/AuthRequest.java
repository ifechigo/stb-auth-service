package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthRequest {
    @Email(message = "Invalid email format")
    private String email;

    @Pattern(regexp = "\\d{11}", message = "phoneNumber field must be exactly 11 digits")
    private String phoneNumber;

    @NotBlank(message = "password field is required")
    private String password;

    @AssertTrue(message = "Either email or phone number field must be provided")
    public boolean isEmailOrPhoneProvided() {
        return (email != null && !email.isBlank()) || (phoneNumber != null && !phoneNumber.isBlank());
    }
}
