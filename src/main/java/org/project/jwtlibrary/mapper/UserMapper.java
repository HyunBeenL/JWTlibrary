package org.project.jwtlibrary.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.project.jwtlibrary.dto.userDTO;

@Mapper
public interface UserMapper {
    userDTO.UserResponseDto findByEmail(String email);
}
