package com.securitysite.securitydemosite.service;

import com.securitysite.securitydemosite.model.Role;
import com.securitysite.securitydemosite.model.User;
import com.securitysite.securitydemosite.repository.RoleRepository;
import com.securitysite.securitydemosite.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Transactional
    public User registerUser(String fullName, String email, String rawPassword) {
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("EMAIL_EXISTS");
        }

        User user = new User();
        user.setFullName(fullName);
        user.setEmail(email);
        user.setPassword(rawPassword); // зберігаємо у відкритому вигляді

        // роль USER
        Role userRole = roleRepository.findByName("USER")
                .orElseGet(() -> {
                    Role r = new Role();
                    r.setName("USER");
                    return roleRepository.save(r);
                });

        user.getRoles().add(userRole);

        return userRepository.save(user);
    }

    public User authenticate(String email, String rawPassword) {
        return userRepository.findByEmail(email)
                .filter(u -> u.getPassword().equals(rawPassword))  // <── виправлено!
                .orElse(null);
    }

    public Optional<User> findById(UUID id) {
        return userRepository.findById(id);
    }
}
