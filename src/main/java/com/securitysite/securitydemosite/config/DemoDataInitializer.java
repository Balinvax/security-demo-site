package com.securitysite.securitydemosite.config;

import com.securitysite.securitydemosite.model.Role;
import com.securitysite.securitydemosite.model.User;
import com.securitysite.securitydemosite.repository.RoleRepository;
import com.securitysite.securitydemosite.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.Transactional;

@Configuration
public class DemoDataInitializer {

    @Bean
    @Transactional
    public org.springframework.boot.CommandLineRunner initDemoUsers(
            UserRepository userRepository,
            RoleRepository roleRepository
    ) {
        return args -> {

            Role userRole = roleRepository.findByName("USER")
                    .orElseGet(() -> {
                        Role r = new Role();
                        r.setName("USER");
                        return roleRepository.save(r);
                    });

            Role adminRole = roleRepository.findByName("ADMIN")
                    .orElseGet(() -> {
                        Role r = new Role();
                        r.setName("ADMIN");
                        return roleRepository.save(r);
                    });

            if (userRepository.findByEmail("user@user.com").isEmpty()) {
                User user = new User();
                user.setFullName("user");
                user.setEmail("user@user.com");
                user.setPassword("user");

                user.getRoles().add(userRole);

                userRepository.save(user);
                System.out.println("[DEMO] Created test user: user/user with role USER");
            }


            if (userRepository.findByEmail("admin@admin.com").isEmpty()) {
                User admin = new User();
                admin.setFullName("admin");
                admin.setEmail("admin@admin.com");
                admin.setPassword("admin");

                admin.getRoles().add(adminRole);
                admin.getRoles().add(userRole);

                userRepository.save(admin);
                System.out.println("[DEMO] Created test admin: admin/admin with roles ADMIN, USER");
            }
        };
    }
}
