package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EncryptedRequest {
    @NotBlank(message = "data field is required and cannot be empty")
    private String data;
}