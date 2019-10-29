package com.webzg.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 配置多个httpSecurity
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled =true
)
public class MultiHttpSecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() {
        //不使用加密
//        return NoOpPasswordEncoder.getInstance();
        //使用加密
        return new BCryptPasswordEncoder();
    }

    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //配置基于内存的用户名和密码
        //第一个用户and密码
        auth.inMemoryAuthentication().withUser("javaboy").password("$2a$10$uaZWSiGDaEebKRsAXMlHYe.anSVO3Gya3LFzZpQGrPst4vHaQlrTS").roles("admin")
                .and()
                .withUser("江南一点雨").password("$2a$10$eipT7DJmgu5nbFLsL1bi4e3YMAV4rEqNUA4i9u5NDQZ2ID4jgVCRq").roles("user");
    }
    @Configuration
    @Order(1)
    public static class AdminSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/admin/**").authorizeRequests().anyRequest().hasAnyRole("admin");
        }
    }

    @Configuration
    public static class OtherSecurityConfig extends WebSecurityConfigurerAdapter{
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest()
                    .authenticated().and()
                    .formLogin()
                    .loginProcessingUrl("/doLogin")
                    .permitAll()
                    .and()
                    .csrf().disable();
        }
    }
}
