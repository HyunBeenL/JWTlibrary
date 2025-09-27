package org.project.jwtlibrary.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/me")
    public Map<String, Object> me(Authentication auth) {
        return Map.of(
                "userId", auth.getName(),
                "authorities", auth.getAuthorities().toString()
        );
    }
}

