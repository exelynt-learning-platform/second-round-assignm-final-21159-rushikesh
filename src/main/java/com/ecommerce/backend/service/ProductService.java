package com.ecommerce.backend.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.ecommerce.backend.entity.Product;
import com.ecommerce.backend.repository.ProductRepository;

@Service
public class ProductService {

    private final ProductRepository repo;

    public ProductService(ProductRepository repo) {
        this.repo = repo;
    }

    // CREATE
    public Product addProduct(Product product) {
        return repo.save(product);
    }

    // GET ALL
    public List<Product> getAllProducts() {
        return repo.findAll();
    }

    // GET BY ID
    public Product getProduct(Long id) {
        return repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found"));
    }

    // UPDATE
    public Product updateProduct(Long id, Product updated) {

        Product product = getProduct(id);

        product.setName(updated.getName());
        product.setDescription(updated.getDescription());
        product.setPrice(updated.getPrice());
        product.setStock(updated.getStock());
        product.setImageUrl(updated.getImageUrl());

        return repo.save(product);
    }

    // DELETE
    public void deleteProduct(Long id) {
        repo.deleteById(id);
    }
}