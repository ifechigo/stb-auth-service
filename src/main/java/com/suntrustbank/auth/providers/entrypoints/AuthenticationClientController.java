package com.suntrustbank.auth.providers.entrypoints;

import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.providers.dtos.CreateTerminalClientRequest;
import com.suntrustbank.auth.providers.dtos.EncryptedRequest;
import com.suntrustbank.auth.providers.services.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthenticationClientController {

    private final ClientService clientService;

    @PostMapping
    public ResponseEntity<BaseResponse<?>> handleClientCreation(@RequestBody CreateTerminalClientRequest request) throws GenericErrorCodeException {
        return ResponseEntity.ok(clientService.createTerminalClient(request));
    }

    @GetMapping("/{terminalSerialNo}")
    public ResponseEntity<BaseResponse<?>> handleGettingTerminal(@PathVariable String terminalSerialNo) throws GenericErrorCodeException {
        return ResponseEntity.ok(clientService.handleFetchingTerminal(terminalSerialNo));
    }


    @PostMapping("/token")
    public ResponseEntity<?> authenticate(@RequestBody @Validated EncryptedRequest request) throws GenericErrorCodeException {
        return ResponseEntity.ok(clientService.loginClient(request));
    }
}
