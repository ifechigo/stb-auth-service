package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import static com.suntrustbank.auth.core.constants.Common.MAXIMUM_PASSWORD_LENGTH;

@Getter
@Setter
public class PasswordUpdateRequest {
    @NotEmpty(message = "Reference is required")
    private String reference;

    @NotBlank(message = "Password is required")
    @Size(min = MAXIMUM_PASSWORD_LENGTH, message = "Password must be at least 8 characters long")
    @Pattern(regexp = "(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&+=!\\*]).*$", message =
            "Password must contain at least one lowercase letter, one uppercase letter, one "
                    + "number, and one special character")
    private String password;
}
