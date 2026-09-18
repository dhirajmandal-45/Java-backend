package ecommerce.back.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import ecommerce.back.entity.Order;
import ecommerce.back.repository.OrderRepository;

@RestController
@RequestMapping("/admin/orders")
public class AdminOrderController {

    private final OrderRepository orderRepository;

    public AdminOrderController(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    // ==========================================
    // GET ALL ORDERS
    // GET /admin/orders
    // ==========================================

    @GetMapping
    public ResponseEntity<List<Order>> getAllOrders() {

        List<Order> orders = orderRepository.findAll();

        return ResponseEntity.ok(orders);
    }

    // ==========================================
    // UPDATE ORDER STATUS
    // PUT /admin/orders/{id}/status
    // ==========================================

    @PutMapping("/{id}/status")
    public ResponseEntity<Order> updateOrderStatus(
            @PathVariable Long id,
            @RequestBody StatusRequest request) {

        Order order = orderRepository
                .findById(id)
                .orElseThrow(() -> new RuntimeException("Order not found"));

        order.setStatus(request.getStatus());

        Order updatedOrder = orderRepository.save(order);

        return ResponseEntity.ok(updatedOrder);
    }

    // ==========================================
    // STATUS REQUEST
    // ==========================================

    public static class StatusRequest {

        private String status;

        public StatusRequest() {
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }
    }
}