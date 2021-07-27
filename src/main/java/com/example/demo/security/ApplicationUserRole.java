package com.example.demo.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.example.demo.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(Course_READ,Course_WRITE,STUDENT_READ,STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(Course_READ,STUDENT_READ));

        private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions(){
        return permissions;
    }

    public Set<GrantedAuthority> getGrantedAuthority(){
        Set<GrantedAuthority>  permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()) )
        .collect(Collectors.toSet());

        permissions.add(new SimpleGrantedAuthority("ROLE_"+ this.name()));

        return permissions;

    }
}
