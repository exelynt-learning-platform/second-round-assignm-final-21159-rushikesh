package com.ecommerce.backend.controller;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ecommerce.backend.entity.Product;
import com.ecommerce.backend.service.ProductService;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final ProductService service;

    public ProductController(ProductService service) {
        this.service = service;
    }

    // CREATE PRODUCT
    @PostMapping(consumes = "application/json")
public Product create(@RequestBody Product product) {
    return service.addProduct(product);
}

    // GET ALL
    @GetMapping
    public List<Product> getAll() {
        return service.getAllProducts();
    }

    // GET BY ID
    @GetMapping("/{id}")
    public Product getOne(@PathVariable Long id) {
        return service.getProduct(id);
    }

    // UPDATE
    @PutMapping("/{id}")
    public Product update(@PathVariable Long id,
                          @RequestBody Product product) {
        return service.updateProduct(id, product);
    }

    // DELETE
    @DeleteMapping("/{id}")
    public String delete(@PathVariable Long id) {
        service.deleteProduct(id);
        return "Product deleted";
    }
}