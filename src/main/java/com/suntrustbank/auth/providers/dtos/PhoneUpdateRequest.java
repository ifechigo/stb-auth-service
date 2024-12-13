package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PhoneUpdateRequest {
    @NotEmpty(message = "Reference is required")
    private String reference;
}
