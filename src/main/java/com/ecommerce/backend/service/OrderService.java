package com.ecommerce.backend.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.ecommerce.backend.entity.Cart;
import com.ecommerce.backend.entity.Order;
import com.ecommerce.backend.entity.Product;
import com.ecommerce.backend.entity.User;
import com.ecommerce.backend.repository.CartRepository;
import com.ecommerce.backend.repository.OrderRepository;
import com.ecommerce.backend.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OrderService {

    private final CartRepository cartRepository;
    private final OrderRepository orderRepository;
    private final UserRepository userRepository;

    //CREATE ORDER FROM CART
    public Order placeOrder(Long userId, String address) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Cart> cartItems = cartRepository.findByUser(user);

        if (cartItems.isEmpty()) {
            throw new RuntimeException("Cart is empty");
        }

        // GET PRODUCTS
        List<Product> products = cartItems.stream()
                .map(Cart::getProduct)
                .toList();

        // CALCULATE TOTAL
        double total = cartItems.stream()
                .mapToDouble(item -> item.getProduct().getPrice() * item.getQuantity())
                .sum();

        // CREATE ORDER
        Order order = new Order();
        order.setUser(user);
        order.setProducts(products);
        order.setTotalPrice(total);
        order.setAddress(address);
        order.setPaymentStatus("PENDING");

        Order savedOrder = orderRepository.save(order);

        // CLEAR CART
        cartRepository.deleteAll(cartItems);

        return savedOrder;
    }

    //GET USER ORDERS
    public List<Order> getUserOrders(Long userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return orderRepository.findByUser(user);
    }
}