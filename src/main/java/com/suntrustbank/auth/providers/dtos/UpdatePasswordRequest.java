package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class UpdatePasswordRequest {
    @NotBlank(message = "oldPassword field is required")
    private String oldPassword;

    @NotBlank(message = "newPassword field is required")
    private String newPassword;
}
