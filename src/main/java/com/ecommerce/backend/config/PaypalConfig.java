package com.ecommerce.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.paypal.base.rest.APIContext;

@Configuration
public class PaypalConfig {
    
    private final String CLIENT_ID = "YOUR_CLIENT_ID";
    private final String CLIENT_SECRET = "YOUR__CLIENT_SECRET";
    private final String MODE = "sandbox"; //

    @Bean
    public APIContext apiContext() {

        // CORRECT WAY
        APIContext context = new APIContext(CLIENT_ID, CLIENT_SECRET, MODE);

        return context;
    }
}