package com.ecommerce.backend.service;

import com.ecommerce.backend.entity.Order;
import com.ecommerce.backend.repository.OrderRepository;
import com.paypal.api.payments.*;
import com.paypal.base.rest.APIContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class PaymentService {

    private final APIContext apiContext;
    private final OrderRepository orderRepository;

    //CREATE PAYPAL PAYMENT
    public String createPayment(Long orderId) {

        try {
            Order order = orderRepository.findById(orderId)
                    .orElseThrow(() -> new RuntimeException("Order not found"));

            Amount amount = new Amount();
            amount.setCurrency("USD");
            amount.setTotal(String.format("%.2f", order.getTotalPrice()));

            Transaction transaction = new Transaction();
            transaction.setDescription("Order Payment");
            transaction.setAmount(amount);

            Payer payer = new Payer();
            payer.setPaymentMethod("paypal");

            Payment payment = new Payment();
            payment.setIntent("sale");
            payment.setPayer(payer);
            payment.setTransactions(Collections.singletonList(transaction));

            RedirectUrls redirectUrls = new RedirectUrls();
            redirectUrls.setCancelUrl("http://localhost:8080/api/payment/cancel");
            redirectUrls.setReturnUrl("http://localhost:8080/api/payment/success");

            payment.setRedirectUrls(redirectUrls);

            Payment createdPayment = payment.create(apiContext);

            // Save paymentId
            order.setPaymentId(createdPayment.getId());
            orderRepository.save(order);

            // Return approval URL
            for (Links link : createdPayment.getLinks()) {
                if (link.getRel().equals("approval_url")) {
                    return link.getHref();
                }
            }

            throw new RuntimeException("No approval URL found");

        } catch (Exception e) {
            throw new RuntimeException("Payment error: " + e.getMessage());
        }
    }

    // payment SUCCESS
    public String successPayment(String paymentId, String payerId) {

        try {
            Payment payment = new Payment();
            payment.setId(paymentId);

            PaymentExecution execution = new PaymentExecution();
            execution.setPayerId(payerId);

            Payment executedPayment = payment.execute(apiContext, execution);

            if (executedPayment.getState().equals("approved")) {

                Order order = orderRepository.findAll().stream()
                        .filter(o -> paymentId.equals(o.getPaymentId()))
                        .findFirst()
                        .orElseThrow();

                order.setPaymentStatus("SUCCESS");
                orderRepository.save(order);

                return "Payment Successful";
            }

        } catch (Exception e) {
            throw new RuntimeException("Payment execution failed");
        }

        return "Payment Failed";
    }

    //Cancel Payment
    public String cancelPayment() {
        return "Payment Cancelled";
    }
}