package com.suntrustbank.auth.providers.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.keycloak.representations.idm.ClientRepresentation;

@Builder
@Getter
@Setter
@AllArgsConstructor
public class TerminalDto {
    private String terminalSerialNo;
    private String terminalSecret;
    private String terminalRef;
    private String terminalName;
    private boolean enabled;

    public static TerminalDto map(ClientRepresentation clientRepresentation) {
        return TerminalDto
                .builder()
                .terminalSerialNo(clientRepresentation.getClientId())
                .terminalSecret(clientRepresentation.getSecret())
                .terminalName(clientRepresentation.getName())
                .enabled(clientRepresentation.isEnabled())
                .terminalRef(clientRepresentation.getId())
                .build();
    }
}