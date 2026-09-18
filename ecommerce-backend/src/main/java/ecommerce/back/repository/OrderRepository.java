package ecommerce.back.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import ecommerce.back.entity.Order;
import ecommerce.back.entity.User;

public interface OrderRepository extends JpaRepository<Order, Long> {

    List<Order> findByUserOrderByCreatedAtDesc(User user);
}