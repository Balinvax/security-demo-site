package com.securitysite.securitydemosite.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // статичні html зі /static
        registry.addViewController("/").setViewName("forward:/index.html");
        registry.addViewController("/login").setViewName("forward:/login.html");
        registry.addViewController("/register").setViewName("forward:/register.html");
        registry.addViewController("/profile").setViewName("forward:/profile.html");
        registry.addViewController("/admin").setViewName("forward:/admin.html");
        registry.addViewController("/404").setViewName("forward:/404.html");
        registry.addViewController("/access-denied").setViewName("forward:/access-denied.html");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Віддаємо все зі static як статику
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/");
    }
}
