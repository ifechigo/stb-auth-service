package com.suntrustbank.auth.providers.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateTerminalClientRequest {
    @NotBlank(message = "terminalSerialNo is required")
    private String terminalSerialNo;

    private String terminalId;
}