package com.suntrustbank.auth.providers.services;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.suntrustbank.auth.providers.dtos.SmsRequest;
import com.suntrustbank.auth.providers.dtos.enums.PublisherDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final RabbitTemplate rabbitTemplate;

    public void sendSMS(SmsRequest smsRequest) {
        try {
            rabbitTemplate.convertAndSend(PublisherDetails.SMS_ROUTING_KEY.getValue(), new ObjectMapper().writeValueAsString(smsRequest)); // Only routing key required
        } catch (Exception e) {
            log.info("==> Failed to publish message. Error: {}",e.getMessage() , e);
        }
    }
}
