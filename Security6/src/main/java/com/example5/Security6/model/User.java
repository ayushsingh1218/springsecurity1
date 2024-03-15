package com.example5.Security6.model;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "User")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class User implements UserDetails{
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "First_name")
    private String firstname;

    @Column(name = "Last_name")
    private String lastname;

    @Column(name = "Username")
    private String username;

    @Column(name = "Password")
    private String password;

    @Enumerated(value = EnumType.STRING)
    Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      return List.of(new SimpleGrantedAuthority(role.name()));
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
