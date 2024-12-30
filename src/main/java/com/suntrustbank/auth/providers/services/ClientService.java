package com.suntrustbank.auth.providers.services;


import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.providers.dtos.CreateTerminalClientRequest;
import com.suntrustbank.auth.providers.dtos.EncryptedRequest;


public interface ClientService {
    BaseResponse createTerminalClient(CreateTerminalClientRequest requestDto) throws GenericErrorCodeException;
    BaseResponse handleFetchingTerminal(String terminalSerialNo) throws GenericErrorCodeException;
    BaseResponse loginClient(EncryptedRequest requestDto) throws GenericErrorCodeException;
}
