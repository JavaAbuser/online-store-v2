package com.javaabuser.onlinestore.repositories;

import com.javaabuser.onlinestore.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    @Query("SELECT user FROM User user WHERE user.email = :email")
    Optional<User> findByEmail(@Param("email") String userEmail);
    Boolean existsUserByEmail(String userEmail);
}

