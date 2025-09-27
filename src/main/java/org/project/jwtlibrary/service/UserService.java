package org.project.jwtlibrary.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.project.jwtlibrary.dto.userDTO;
import org.project.jwtlibrary.mapper.UserMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();
    private static Long id;
    private static String role;
    public boolean verify(String username, String raw) {
        userDTO.UserResponseDto dto = userMapper.findByEmail(username);
        if(dto == null){
            return false;
        }

        id = Long.valueOf(dto.getId());
        role = dto.getRole();
        var enc = dto.getPassword();
//        var enc = users.get(username);
        return enc != null && encoder.matches(raw, enc);
    }

    public Long userIdOf(String username) { return id; }

    public List<String> rolesOf(String username) { return List.of(role); }
}
