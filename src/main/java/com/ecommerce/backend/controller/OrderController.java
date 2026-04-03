package com.ecommerce.backend.controller;

import com.ecommerce.backend.entity.Order;
import com.ecommerce.backend.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/orders")
@RequiredArgsConstructor
public class OrderController {

    private final OrderService orderService;

    // PLACE ORDER
    @PostMapping("/place")
    public Order placeOrder(
            @RequestParam Long userId,
            @RequestParam String address) {

        return orderService.placeOrder(userId, address);
    }

    // GET ORDERS
    @GetMapping("/{userId}")
    public List<Order> getOrders(@PathVariable Long userId) {
        return orderService.getUserOrders(userId);
    }
}