package com.suntrustbank.auth.providers.dtos;

import com.suntrustbank.auth.providers.dtos.enums.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthCreationRequest {
    @NotBlank(message = "userId is required")
    private String userId;

    @NotBlank(message = "pin is required")
    @Pattern(regexp = "\\d{4}", message = "pin number must be 4 digits")
    private String pin;

    @NotBlank(message = "phone number is required")
    @Pattern(regexp = "\\d{11}", message = "phoneNumber field must be exactly 11 digits")
    private String phoneNumber;

    private String firstName;
    private String lastName;

    private Role role;
}
