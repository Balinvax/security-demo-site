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

            // ---------- 1. Переконуємось, що є ролі USER і ADMIN ----------

            Role userRole = roleRepository.findByName("USER")
                    .orElseGet(() -> {
                        Role r = new Role();
                        r.setName("USER");          // або "ROLE_USER", якщо так у тебе заведено
                        return roleRepository.save(r);
                    });

            Role adminRole = roleRepository.findByName("ADMIN")
                    .orElseGet(() -> {
                        Role r = new Role();
                        r.setName("ADMIN");         // або "ROLE_ADMIN"
                        return roleRepository.save(r);
                    });

            // ---------- 2. Створюємо користувача user/user ----------

            if (userRepository.findByEmail("user@user.com").isEmpty()) {  // якщо метод інший — підправь тут
                User user = new User();
                user.setFullName("user");
                user.setEmail("user@user.com");
                user.setPassword("user");   // якщо потім додаси хешування — змінемо

                // додамо роль USER
                user.getRoles().add(userRole);

                userRepository.save(user);
                System.out.println("[DEMO] Created test user: user/user with role USER");
            }

            // ---------- 3. Створюємо користувача admin/admin ----------

            if (userRepository.findByEmail("admin@admin.com").isEmpty()) {
                User admin = new User();
                admin.setFullName("admin");
                admin.setEmail("admin@admin.com");
                admin.setPassword("admin");

                // додамо роль ADMIN (і, за бажанням, USER теж)
                admin.getRoles().add(adminRole);
                admin.getRoles().add(userRole);

                userRepository.save(admin);
                System.out.println("[DEMO] Created test admin: admin/admin with roles ADMIN, USER");
            }
        };
    }
}
