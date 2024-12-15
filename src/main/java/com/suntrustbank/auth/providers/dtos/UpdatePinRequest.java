package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import static com.suntrustbank.auth.core.constants.Common.PIN_LENGTH;

@Getter
@Setter
public class UpdatePinRequest {
    private String oldPin;

    @NotBlank(message = "pin is required")
    @Size(min = PIN_LENGTH, message = "pin must be 4 digits")
    @Pattern(regexp = "\\d{4}", message = "pin number must be 4 digits")
    private String newPin;
}
