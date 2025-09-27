package org.project.jwtlibrary.web;

import org.project.jwtlibrary.dto.LoginRequest;
import org.project.jwtlibrary.dto.TokenResponse;
import org.project.jwtlibrary.service.InMemoryUserService;
import org.project.jwtlibrary.service.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.project.jwtlibrary.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

//    private final InMemoryUserService userService;
    private final UserService userService;
    private final JwtService jwt;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest req, HttpServletResponse res) {
        if (!userService.verify(req.username(), req.password())) {
            return ResponseEntity.status(401).build();
        }
        Long userId = userService.userIdOf(req.username());
        List<String> roles = userService.rolesOf(req.username());

        String access = jwt.generateAccess(userId, req.username(), roles);
        String refresh = jwt.generateRefresh(userId);
        ResponseCookie cookie = jwt.refreshCookie(refresh);
        res.addHeader("Set-Cookie", cookie.toString());

        long exp = System.currentTimeMillis()/1000 + 60*30;
        return ResponseEntity.ok(new TokenResponse(access, exp));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@CookieValue(name="refreshToken", required=false) String rt,
                                                 HttpServletResponse res) {
        if (rt == null || rt.isBlank()) return ResponseEntity.status(401).build();
        try {
            var auth = jwt.toAuthentication(rt);
            Long userId = Long.valueOf((String) auth.getPrincipal());
            String access = jwt.generateAccess(userId, "user@local", List.of("USER"));
            String newRefresh = jwt.generateRefresh(userId);
            res.addHeader("Set-Cookie", jwt.refreshCookie(newRefresh).toString());
            long exp = System.currentTimeMillis()/1000 + 60*30;
            return ResponseEntity.ok(new TokenResponse(access, exp));
        } catch (Exception e) {
            return ResponseEntity.status(401).build();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse res) {
        res.addHeader("Set-Cookie", jwt.clearRefreshCookie().toString());
        return ResponseEntity.noContent().build();
    }
}

