package com.hstn.sec.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;


@Configuration
public class MySecurityConfiguration {

//    @Bean
//    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
//
//        UserDetails anna = User.builder()
//                .username("Anna").password("{noop}anna123").roles("USER")
//                .build();
//        UserDetails boris = User.builder()
//                .username("Boris").password("{noop}boris123").roles("USER", "MANAGER")
//                .build();
//        UserDetails victor = User.builder()
//                .username("Victor").password("{noop}victor123").roles("USER", "MANAGER", "ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(anna, boris, victor);
//
//    }
////    Закомментировали с того момента как нам стало необходимо брать пароли и роли из БД

//    @Bean
//    public UserDetailsManager userDetailsManager(DataSource dataSource) {
//        return new JdbcUserDetailsManager(dataSource);
//    }
//// После того как мы создали и стали использовать свои таблице в БД

    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.setUsersByUsernameQuery("select client_name, pass, enabled from clients where client_name=?");
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery("select client_name, role from roles where client_name=?");

        return jdbcUserDetailsManager;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(configurer ->
                        configurer
                                .requestMatchers("/").hasRole("USER")
//  т.е. на страницу http://localhost:8080/ могут переходить
//  все пользователи, имеющие роль USER
                                .requestMatchers("/managers/**").hasRole("MANAGER")
//  т.е. на страницу http://localhost:8080/managers и все подстраницы (/**)
//  могут переходить все пользователи, имеющие роль USER
                                .requestMatchers("/admins/**").hasRole("ADMIN")
//  т.е. на страницу http://localhost:8080/admins и все подстраницы (/**)
//  могут переходить все пользователи, имеющие роль ADMIN
                                .anyRequest().authenticated())
                // Верхние три строки кода показывают, что все
                // запросы к нашему приложению должны быть аутентифицированы
                // т.е. пользователь, который зашёл в приложение должен залогиниться
                .formLogin(form ->
                        form.loginPage("/myLoginPage")
                                // Это URL своей, недефолтной формы для логина
                                .loginProcessingUrl("/authenticateUser")
                                // Здесь указывается URL, который мы будем обрабатывать
                                .permitAll())
                // Эта верхняя строка означает, что на форму для логина
                // может зайти любой, а чтобы пойти дальше нужно будет залогиниться
                .logout(logout -> logout.permitAll()
                )
                .exceptionHandling(configurer ->
                        configurer.accessDeniedPage("/access-denied-page")


                );
        return http.build();
    }
}
