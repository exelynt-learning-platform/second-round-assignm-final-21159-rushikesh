package com.ecommerce.backend.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "cart")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Cart {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    //USER
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    //PRODUCT
    @ManyToOne
    @JoinColumn(name = "product_id")
    private Product product;

    //QUANTITY
    private int quantity;
}