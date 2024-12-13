package com.suntrustbank.auth.core.utils.jwt;

import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static com.suntrustbank.auth.core.constants.Common.BEARER;

@Slf4j
@Service
public class JwtUtil {

    private static final int MAX_LENGTH = 3;

    /**
     * Gets the specified data value from
     * the authentication token by providing the
     * key name e.g 'email', 'sub' e.t.c.
     *
     * @param authorizationHeader
     * @param fieldKeyName
     * @return
     * @throws GenericErrorCodeException
     */
    public Optional<?> extractAllClaims(String authorizationHeader, String fieldKeyName) {
        try {
            String[] parts = authorizationHeader.split(" ");
            if (parts.length != 2 || !parts[0].equalsIgnoreCase(BEARER)) {
                return Optional.empty();
            }

            String token = parts[1];
            String[] tokenParts = token.split("\\.");
            if (tokenParts.length != MAX_LENGTH) {
                return Optional.empty();
            }

            String payload = new String(Base64.getUrlDecoder().decode(tokenParts[1]));
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> payloadMap = objectMapper.readValue(payload, Map.class);

            if (payloadMap.containsKey(fieldKeyName)) {
                return Optional.of(payloadMap.get(fieldKeyName));
            } else {
                log.error("Field key not found in token");
                return Optional.empty();
            }
        } catch (Exception e) {
            log.error("Error occurred when decoding token: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
