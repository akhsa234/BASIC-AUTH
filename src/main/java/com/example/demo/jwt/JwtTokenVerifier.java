package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


public class JwtTokenVerifier extends OncePerRequestFilter {

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public JwtTokenVerifier(SecretKey secretKey, JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filter) throws ServletException, IOException {
       String authorizationHeader= request.getHeader(jwtConfig.getAuthorizationHeader());

        if(Strings.isNullOrEmpty( authorizationHeader) ||
            !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())){
            filter.doFilter(request,response);
            return;
        }

        String token= authorizationHeader.replace( jwtConfig.getTokenPrefix(), "");
        try {

//            String secretKey = "harryPotterharryPotterharryPotterharryPotterharryPotterharryPotter";

            Jws<Claims> claimsJws = Jwts.parser()
                                        .setSigningKey(secretKey)
                                        .parseClaimsJws(token);

            Claims body=claimsJws.getBody();
            String username= body.getSubject();
            /*
                "sub": "linda",
             "authorities": [ { "authority": "student:write" }, {"authority": " course:read" },
                              { "authority": "student:read" }, {"authority": "ROLE_ADMIN"},
                                 {"authority": " course:write"}],
                "iat": 1627634215,
                "exp": 1626377400
                }

             */
            List<Map<String,String>> authorities=  (List<Map<String,String>>) body.get("authorities");
            Set<SimpleGrantedAuthority> simpleGrantedAuthority = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthority
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }catch (JwtException e)
        {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }

        filter.doFilter(request, response);
    }
}
