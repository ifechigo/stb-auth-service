package com.suntrustbank.auth.core.configs.rabbitmq;


import com.suntrustbank.auth.providers.dtos.enums.PublisherDetails;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class RabbitMQPublisherConfig {

    @Bean
    public TopicExchange notificationExchange() {
        return ExchangeBuilder.topicExchange(PublisherDetails.NOTIFICATION_EXCHANGE_NAME.getValue())
                .durable(true)
                .build();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setExchange(PublisherDetails.NOTIFICATION_EXCHANGE_NAME.getValue());
        return rabbitTemplate;
    }
}
