package com.ecommerce.backend.controller;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ecommerce.backend.entity.Cart;
import com.ecommerce.backend.service.CartService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/cart")
@RequiredArgsConstructor
public class CartController {

    private final CartService cartService;

    //ADD TO CART
    @PostMapping("/add")
    public Cart addToCart(
            @RequestParam Long userId,
            @RequestParam Long productId,
            @RequestParam int quantity) {

        return cartService.addToCart(userId, productId, quantity);
    }

    // GET CART
    @GetMapping("/{userId}")
    public List<Cart> getCart(@PathVariable Long userId) {
        return cartService.getUserCart(userId);
    }

    // UPDATE
    @PutMapping("/{cartId}")
    public Cart updateCart(
            @PathVariable Long cartId,
            @RequestParam int quantity) {

        return cartService.updateCart(cartId, quantity);
    }

    //DELETE
    @DeleteMapping("/{cartId}")
    public String delete(@PathVariable Long cartId) {
        cartService.removeFromCart(cartId);
        return "Item removed from cart";
    }
}