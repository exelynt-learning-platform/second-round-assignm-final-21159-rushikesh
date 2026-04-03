package com.ecommerce.backend.controller;

import com.ecommerce.backend.service.PaymentService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/payment")
@RequiredArgsConstructor
public class PaymentController {

    private final PaymentService paymentService;

    // CREATE PAYMENT
    @PostMapping("/create")
    public String createPayment(@RequestParam Long orderId) {
        return paymentService.createPayment(orderId);
    }

    // SUCCESS
    @GetMapping("/success")
    public String success(
            @RequestParam String paymentId,
            @RequestParam String PayerID) {

        return paymentService.successPayment(paymentId, PayerID);
    }

    //CANCEL
    @GetMapping("/cancel")
    public String cancel() {
        return paymentService.cancelPayment();
    }
}