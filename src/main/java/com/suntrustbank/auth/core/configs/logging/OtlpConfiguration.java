package com.suntrustbank.auth.core.configs.logging;

import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter;
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporterBuilder;
import org.springframework.boot.actuate.autoconfigure.tracing.otlp.OtlpProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map.Entry;

@Configuration
public class OtlpConfiguration {

    @Bean
    public OtlpGrpcSpanExporter otlpGrpcSpanExporter(final OtlpProperties properties) {
        final OtlpGrpcSpanExporterBuilder builder = OtlpGrpcSpanExporter.builder()
                .setEndpoint(properties.getEndpoint())
                .setTimeout(properties.getTimeout());
        for (Entry<String, String> header : properties.getHeaders().entrySet()) {
            builder.addHeader(header.getKey(), header.getValue());
        }
        return builder.build();
    }
}
