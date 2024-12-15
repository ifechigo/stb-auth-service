package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Objects;

@Getter
@Setter
public class PinUpdateRequest {
    @NotEmpty(message = "reference is required")
    private String reference;

    @NotBlank(message = "pin is required")
    @Pattern(regexp = "\\d{4}", message = "new pin must be 4 digits")
    private String newPin;

    @NotBlank(message = "pin is required")
    @Pattern(regexp = "\\d{4}", message = "confirm new pin must be 4 digits")
    private String confirmNewPin;

    @AssertTrue(message = "the pins provided do not match")
    public boolean isPinMatch() {
        return (Objects.equals(newPin, confirmNewPin));
    }
}
