package com.securitysite.securitydemosite.service;

import com.securitysite.securitydemosite.model.Role;
import com.securitysite.securitydemosite.model.User;
import com.securitysite.securitydemosite.repository.RoleRepository;
import com.securitysite.securitydemosite.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User registerUser(String fullName, String email, String rawPassword) {
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("EMAIL_EXISTS");
        }

        User user = new User();
        user.setFullName(fullName);
        user.setEmail(email);

        // 🔐 ТЕПЕР ЗБЕРІГАЄМО НЕ СИРИЙ ПАРОЛЬ, А ХЕШ
        String encoded = passwordEncoder.encode(rawPassword);
        user.setPassword(encoded);

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

    @Transactional
    public User authenticate(String email, String rawPassword) {
        Optional<User> opt = userRepository.findByEmail(email);
        if (opt.isEmpty()) {
            return null;
        }

        User user = opt.get();
        String stored = user.getPassword();

        if (stored == null) {
            return null;
        }

        // 1) Нормальний випадок: пароль уже захешований (BCrypt)
        if (passwordEncoder.matches(rawPassword, stored)) {
            return user;
        }

        // 2) МІГРАЦІЯ: якщо в БД ще лежить старий "голий" пароль
        //    тобто збережене значення == введеному зараз
        if (stored.equals(rawPassword)) {
            String encoded = passwordEncoder.encode(rawPassword);
            user.setPassword(encoded);
            userRepository.save(user);
            System.out.println("MIGRATED PLAIN PASSWORD TO BCRYPT FOR USER " + email);
            return user;
        }

        // 3) Пароль не підійшов
        return null;
    }

    public Optional<User> findById(UUID id) {
        return userRepository.findById(id);
    }
}
