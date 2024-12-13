package com.suntrustbank.auth.providers.dtos;

import com.suntrustbank.auth.providers.dtos.enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import static com.suntrustbank.auth.core.constants.Common.MAXIMUM_PASSWORD_LENGTH;

@Getter
@Setter
@Builder
public class AuthCreationRequest {
    @NotBlank(message = "Email address is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = MAXIMUM_PASSWORD_LENGTH, message = "Password must be at least 8 characters long")
    @Pattern(regexp = "(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&+=!\\*]).*$", message =
            "Password must contain at least one lowercase letter, one uppercase letter, one "
                    + "number, and one special character")
    private String password;
    private String firstName;
    private String lastName;

    @NotBlank(message = "referenceId is required")
    private String referenceId;

    private Role role;
}
