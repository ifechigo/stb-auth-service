package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class UpdatePinRequest {
    @NotBlank(message = "oldPin field is required")
    private String oldPin;

    @NotBlank(message = "newPin field is required")
    private String newPin;
}
