package com.javaabuser.onlinestore.services;

import com.javaabuser.onlinestore.exceptions.user.UserNotFoundException;
import com.javaabuser.onlinestore.models.User;
import com.javaabuser.onlinestore.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class UserService {
    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> findById(int customerId){
        return userRepository.findById(customerId);
    }

    public Optional<User> findByEmail(String userEmail){
        Optional<User> user = userRepository.findByEmail(userEmail);
        if(user.isEmpty()){
            throw new UserNotFoundException();
        }
        return user;
    }

    public boolean existsUserByEmail(String userEmail){
        return userRepository.existsUserByEmail(userEmail);
    }

    @Transactional
    public void save(User user){
        userRepository.save(user);
    }
}
