package org.project.jwtlibrary.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.List;

@Service
@RequiredArgsConstructor
public class InMemoryUserService {
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    // username = user@local, password = pass1234
    private final Map<String, String> users = Map.of(
            "user@local", "$2a$10$VosxB/3U0aHM79v6yM.c7uPxfIHIxsuKZBcQKt4KDbOycGIvS.Mrq"
    );

    public boolean verify(String username, String raw) {
        var enc = users.get(username);
        return enc != null && encoder.matches(raw, enc);
    }

    public Long userIdOf(String username) { return 1L; }

    public List<String> rolesOf(String username) { return List.of("USER"); }
}

