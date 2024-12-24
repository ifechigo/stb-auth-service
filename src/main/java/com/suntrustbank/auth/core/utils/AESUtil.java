package com.suntrustbank.auth.core.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.suntrustbank.auth.core.enums.ErrorCode;
import com.suntrustbank.auth.core.errorhandling.exceptions.GenericErrorCodeException;
import io.micrometer.common.util.StringUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


@Slf4j
@Getter
@Configuration
public class AESUtil {

    @Value("${spring.encryption.passphrase}")
    private String passphrase;

    @Value("${spring.encryption.salt}")
    private String salt;

    private static final String AES_ALGORITHM = "AES";
    private static final String PWH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private final ObjectMapper objectMapper = new ObjectMapper();

    private char[] getPassphrase() {
        if (StringUtils.isBlank(passphrase)) {
            log.info("No passphrase parsed");
            return null;
        }
        log.info("Passphrase parsed");
        return passphrase.toCharArray();
    }

    // Derive AES Key from a Passphrase
    private SecretKey deriveKey() throws GenericErrorCodeException {
        try {
            PBEKeySpec spec = new PBEKeySpec(getPassphrase(), salt.getBytes(), 65536, 128);

            SecretKeyFactory factory = SecretKeyFactory.getInstance(PWH_ALGORITHM);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, AES_ALGORITHM);
        } catch (Exception e) {
            log.info("Error Generating key:: {}", e.getMessage(), e);
            throw GenericErrorCodeException.badRequest("failed to derive key");
        }
    }

    // Encrypt data
    public String encrypt(String data) throws GenericErrorCodeException {
        SecretKey key = deriveKey();
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            log.info("Error Encrypting data:: {}", e.getMessage(), e);
            throw new GenericErrorCodeException("encryption failed", ErrorCode.BAD_REQUEST, HttpStatus.BAD_REQUEST);
        }
    }

    public String encrypt(Object data) throws Exception {
        SecretKey key = deriveKey();
        try {
            String jsonData = (data instanceof String)
                    ? (String) data
                    : objectMapper.writeValueAsString(data);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(jsonData.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            log.info("Error Encrypting data:: {}", e.getMessage(), e);
            throw new Exception("encryption failed", e);
        }
    }

    // Decrypt data
    public <T> T decrypt(String encryptedData, Class<T> targetType) throws GenericErrorCodeException {
        SecretKey key = deriveKey();
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            String decryptedString = new String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8);

            // Check if the decrypted string is JSON
            if (isValidJson(decryptedString)) {
                return objectMapper.readValue(decryptedString, targetType);
            } else {
                // Return as a plain string
                return (T) decryptedString;
            }
        } catch (Exception e) {
            log.info("Error Decrypting data:: {}", e.getMessage(), e);
            throw GenericErrorCodeException.badRequest("invalid request");
        }
    }

    private boolean isValidJson(String data) {
        try {
            objectMapper.readTree(data);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}