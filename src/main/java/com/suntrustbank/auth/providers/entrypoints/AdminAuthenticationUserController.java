package com.suntrustbank.auth.providers.entrypoints;

import com.suntrustbank.auth.core.dtos.BaseResponse;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.suntrustbank.auth.core.utils.jwt.JwtUtil;
import com.suntrustbank.auth.providers.dtos.*;
import com.suntrustbank.auth.providers.services.AdminAccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import static com.suntrustbank.auth.core.constants.Common.USER_NAME;

@RestController
@RequestMapping("/v1/auth/admin")
@RequiredArgsConstructor
public class AdminAuthenticationUserController {

    private final AdminAccountService adminAccountService;
    private final JwtUtil jwtService;

    @PostMapping("/signup")
    public ResponseEntity createUser(@RequestBody @Validated AuthCreationRequest authCreationRequest) throws GenericErrorCodeException {
        return ResponseEntity.ok(adminAccountService.createUser(authCreationRequest));
    }

    @PostMapping("/token")
    public BaseResponse authenticate(@RequestBody @Validated EncryptedRequest request) throws GenericErrorCodeException {
        return adminAccountService.loginUser(request);
    }


    @PutMapping("/update/email/{email}")
    public ResponseEntity verifyEmail(@RequestHeader("Authorization") String authorizationHeader,
                                      @PathVariable String email) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, USER_NAME).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(adminAccountService.updateEmail(userId, email));
    }

    @PutMapping("/update/phone/{phoneNumber}")
    public ResponseEntity updatePhoneNumber(@RequestHeader("Authorization") String authorizationHeader,
                                            @PathVariable String phoneNumber) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, USER_NAME).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(adminAccountService.updatePhoneNumber(userId, phoneNumber));
    }

    @PutMapping("/update/profile")
    public ResponseEntity update(@RequestHeader("Authorization") String authorizationHeader,
                                 @RequestBody UpdateRequest requestDto) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, USER_NAME).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(adminAccountService.update(userId, requestDto));
    }

    @PutMapping("/update/pin")
    public ResponseEntity updatePin(@RequestHeader("Authorization") String authorizationHeader,
                                    @RequestBody @Validated UpdatePinRequest requestDto) throws GenericErrorCodeException {
        var userId = (String) jwtService.extractAllClaims(authorizationHeader, USER_NAME).orElseThrow(GenericErrorCodeException::unAuthorizedToken);
        return ResponseEntity.ok(adminAccountService.updatePin(userId, requestDto));
    }


    @PostMapping("/pin-reset")
    public ResponseEntity resetPin(@RequestBody @Validated PinResetRequest pinResetRequestDto) throws GenericErrorCodeException {
        return ResponseEntity.ok(adminAccountService.pinReset(pinResetRequestDto));
    }

    @PostMapping("/pin-reset/verify")
    public ResponseEntity verifyPinUpdate(@RequestBody @Validated PinResetOtpRequest pinResetOtpRequest) throws GenericErrorCodeException {
        return ResponseEntity.ok(adminAccountService.verifyPinResetOtp(pinResetOtpRequest));
    }

    @PutMapping("/pin-reset")
    public ResponseEntity saveNewPin(@RequestBody @Validated PinUpdateRequest pinUpdateRequestDto) throws GenericErrorCodeException {
        return ResponseEntity.ok(adminAccountService.saveNewPin(pinUpdateRequestDto));
    }
}
