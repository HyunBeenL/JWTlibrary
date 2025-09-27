package org.project.jwtlibrary.dto;

public record TokenResponse(String accessToken, long expiresAtEpochSec) {
}
