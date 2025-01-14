package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class PasswordUpdateRequest {
    @NotBlank(message = "reference is required")
    private String reference;

    @NotBlank(message = "password field is required")
    private String password;
}
