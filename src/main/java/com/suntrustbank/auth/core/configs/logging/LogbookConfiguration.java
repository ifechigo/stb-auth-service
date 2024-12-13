package com.suntrustbank.auth.core.configs.logging;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.zalando.logbook.CorrelationId;
import org.zalando.logbook.Logbook;

import java.util.Objects;
import java.util.UUID;

import static org.zalando.logbook.core.HeaderFilters.authorization;
import static org.zalando.logbook.core.QueryFilters.accessToken;

@Configuration
public class LogbookConfiguration {

    private static final String TRACEPARENT = "traceparent";

    @Bean
    public CorrelationId correlationId() {

        return request -> {
            final String requestId = request.getHeaders().getFirst(TRACEPARENT);
            return Objects.toString(requestId, UUID.randomUUID().toString());
        };
    }

    @Bean
    public Logbook logbook() {

        return instance();
    }

    public static Logbook instance() {

        return Logbook.builder()
                .queryFilter(accessToken())
                .headerFilter(authorization())
                .build();
    }
}
