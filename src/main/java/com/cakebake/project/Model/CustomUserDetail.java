package com.cakebake.project.Model;

// public class CustomUserDetail extends User implements UserDetails {

//     public CustomUserDetail(User user) {
//         super(user);
//     }

//     @Override
//     public Collection<? extends GrantedAuthority> getAuthorities() {
//         List<GrantedAuthority> authorityList = new ArrayList<>();
//         super.getRoles().forEach(role -> {
//             authorityList.add(new SimpleGrantedAuthority(role.getName()));
//         });
//         return authorityList;
//     }

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CustomUserDetail implements UserDetails {

    private User user;

    public CustomUserDetail(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorityList.add(new SimpleGrantedAuthority(role.getName()));
        });
        return authorityList;
        // return new ArrayList<>();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}