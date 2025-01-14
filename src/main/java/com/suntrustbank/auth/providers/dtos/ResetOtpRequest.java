package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetOtpRequest {
    @NotBlank(message = "reference is required")
    private String reference;

    @NotBlank(message = "otp is required")
    private String otp;
}
