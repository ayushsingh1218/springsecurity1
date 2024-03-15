package com.example5.Security6.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example5.Security6.model.User;

public interface UserRepository extends JpaRepository<User,Long>{

    Optional<User> findByUsername(String Username);
    
}
