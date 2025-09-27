package org.project.jwtlibrary.dto;

import lombok.Builder;
import lombok.Data;


public class userDTO {

    @Data
    public static class UserResponseDto {
        private int id;
        private String name;
        private String password;
        private String role;
        private String email;
    }
}
