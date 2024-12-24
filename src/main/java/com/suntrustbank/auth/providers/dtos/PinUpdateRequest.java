package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class PinUpdateRequest {
    @NotBlank(message = "reference is required")
    private String reference;

    @NotBlank(message = "pin field is required")
    private String pin;
}
