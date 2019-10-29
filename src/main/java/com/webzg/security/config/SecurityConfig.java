package com.webzg.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     *告诉系统我的密码不加密
     * @return
     */
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
    /**
     * 自己定义用户名和密码
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //配置基于内存的用户名和密码
        //第一个用户and密码
        auth.inMemoryAuthentication().withUser("javaboy").password("123").roles("admin")
                .and()
                .withUser("江南一点雨").password("456").roles("user");
    }

    /**
     * 给路径配置角色
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //antMatchers("/admin/**").hasRole("admin")  admin/**路径必须有admin角色才能访问
        //antMatchers("user/**").hasAnyRole("admin","user")  user/**路径必须有admin、user角色才能访问
        //antMatchers("/user/**").access("hasAnyRole('user','admin')")和上面那个一样
        //anyRequest().authenticated() 剩下的其他请求都是登录之后就能访问
        //formLogin().loginProcessingUrl().permitAll 如果是处理登录的url:doLogin，就不拦截，直接通过
        //loginPage 定制登录页面
        //successHandler 登录成功后返回json数据 适合前后端分离
        //failureHandler登录失败
        //.successForwardUrl()登录成功后跳转到登录页面 适合前后端不分流
        //.usernameParameter("uname") .passwordParameter("passwd") url中的username改为uname password改为passwd
        //csrf().disable()关闭csrf攻击
        //.logout() 注销方法
        // .logoutUrl("/logout") 注销url
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("user/**").hasAnyRole("admin","user")
                .antMatchers("/user/**").access("hasAnyRole('user','admin')")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/doLogin")
                .loginPage("/login")
                .usernameParameter("uname")
                .passwordParameter("passwd")
                .successHandler(new AuthenticationSuccessHandler() {
                    //authentication 保存用户成功的信息
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req,HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out=resp.getWriter();
                        Map<String,Object> map=new HashMap<String,Object>();
                        map.put("statu",200);
                        map.put("msg",authentication.getPrincipal());
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    //注销之后的操作
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException e) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out=resp.getWriter();
                        Map<String,Object> map=new HashMap<String,Object>();
                        map.put("statu",401);
                        if(e instanceof LockedException){
                            //LockedException 账户被锁定异常
                            map.put("msg","账户被锁定，登录失败");
                        }else if(e instanceof BadCredentialsException){
                            //BadCredentialsExcept错误的凭证
                            map.put("msg","用户名或密码输入错误，登录失败");
                        }else if(e instanceof DisabledException){
                            //DisabledException 账户被禁用，禁用失败
                            map.put("msg","账户被禁用，登录失败");
                        }else if(e instanceof AccountExpiredException){
                            //AccountExpiredException 账户过期，登录失败
                            map.put("msg","账户过期，登录失败");
                        }else if (e instanceof CredentialsExpiredException){
                            map.put("msg","密码过期，登录失败");
                        }else{
                            map.put("msg","登录失败!");
                        }
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out=resp.getWriter();
                        Map<String,Object> map=new HashMap<String,Object>();
                        map.put("statu",200);
                        map.put("msg","注销登录成功!");
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .and()
                .csrf().disable();
    }
}
