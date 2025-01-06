package com.suntrustbank.auth.providers.services.impl;

import com.suntrustbank.auth.core.configs.properties.AuthConfig;
import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.enums.BaseResponseMessage;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.core.utils.AESEncryptionUtils;
import com.suntrustbank.auth.core.utils.FieldValidatorUtil;
import com.suntrustbank.auth.providers.dtos.CreateTerminalClientRequest;
import com.suntrustbank.auth.providers.dtos.AuthTerminalRequestDto;
import com.suntrustbank.auth.providers.dtos.AuthTokenResponse;
import com.suntrustbank.auth.providers.dtos.TerminalDto;
import com.suntrustbank.auth.providers.dtos.EncryptedRequest;
import com.suntrustbank.auth.providers.services.ClientService;
import com.suntrustbank.auth.providers.services.KeycloakService;
import io.micrometer.common.util.StringUtils;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class ClientServiceImpl implements ClientService {
    private final ClientsResource clientResource;
    private final KeycloakService keycloakService;
    private final AuthConfig authConfig;

    @Override
    public BaseResponse createTerminalClient(CreateTerminalClientRequest requestDto) throws GenericErrorCodeException {
        ClientRepresentation representation = getClientRepresentation(requestDto);

        Response clientCreationResponse = clientResource.create(representation);
        if (clientCreationResponse.getStatus() == HttpStatus.SC_CREATED) {
            return BaseResponse.success(TerminalDto.map(clientResource.findByClientId(requestDto.getTerminalSerialNo()).getFirst()), BaseResponseMessage.SUCCESSFUL);
        }

        if (clientCreationResponse.getStatus() == HttpStatus.SC_CONFLICT) {
            return BaseResponse.success(TerminalDto.map(clientResource.findByClientId(requestDto.getTerminalSerialNo()).getFirst()), BaseResponseMessage.SUCCESSFUL);
        }

        throw GenericErrorCodeException.serverError();
    }

    @Override
    public BaseResponse handleFetchingTerminal(String terminalSerialNo) throws GenericErrorCodeException {
        List<ClientRepresentation> clientRepresentations = clientResource.findByClientId(terminalSerialNo);

        if (clientRepresentations.isEmpty()) {
            throw GenericErrorCodeException.clientNotFound();
        }

        TerminalDto terminalDto = TerminalDto.map(clientRepresentations.getFirst());

        return BaseResponse.success(AESEncryptionUtils.encrypt(authConfig.getPassphrase(), authConfig.getSalt(), terminalDto), BaseResponseMessage.SUCCESSFUL);
    }

    @Override
    public BaseResponse loginClient(EncryptedRequest requestDto) throws GenericErrorCodeException {
        AuthTerminalRequestDto authTerminalRequestDto = AESEncryptionUtils.decrypt(authConfig.getPassphrase(), authConfig.getSalt(), requestDto.getData(), AuthTerminalRequestDto.class);
        FieldValidatorUtil.validate(requestDto);

        List<ClientRepresentation> resource = clientResource.findByClientId(authTerminalRequestDto.getTerminalSerialNo());

        if (resource.isEmpty()) {
            throw GenericErrorCodeException.unAuthorized();
        }

        AuthTokenResponse tokenResponse = keycloakService.loginClient(authTerminalRequestDto.getTerminalSerialNo(), resource.getFirst().getSecret());

        return BaseResponse.success(AESEncryptionUtils.encrypt(authConfig.getPassphrase(), authConfig.getSalt(), tokenResponse), BaseResponseMessage.SUCCESSFUL);
    }

    private static ClientRepresentation getClientRepresentation(CreateTerminalClientRequest requestDto) {
        ClientRepresentation representation = new ClientRepresentation();
        representation.setClientId(requestDto.getTerminalSerialNo());
        if (StringUtils.isNotBlank(requestDto.getTerminalId())) {
            representation.setName(requestDto.getTerminalId());
        }
        representation.setEnabled(true);
        representation.setClientAuthenticatorType("client-secret");
        representation.setProtocol("openid-connect");
        representation.setPublicClient(false);
        representation.setDirectAccessGrantsEnabled(true);
        representation.setServiceAccountsEnabled(true);
        return representation;
    }
}
