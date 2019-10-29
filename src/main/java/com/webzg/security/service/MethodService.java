package com.webzg.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * @ClassName MethodService
 * @Description: TODO
 * @Author Administrator
 * @Date 2019/10/29 0029
 * @Version V1.0
 **/
@Service
public class MethodService {
    @PreAuthorize("hasRole('admin')")
    public String admin(){
        return "hello admin";
    }

    @Secured("ROLE_user")
    public String user(){
        return "hello user";
    }

    @PreAuthorize("hasAnyRole('admin','user')")
    public String hello(){
        return "hello hello";
    }
}
