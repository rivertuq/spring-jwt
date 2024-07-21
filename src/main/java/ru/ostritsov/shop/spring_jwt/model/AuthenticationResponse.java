package ru.ostritsov.shop.spring_jwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class AuthenticationResponse {

    @JsonProperty("access_token")
    private String accesstoken;

    @JsonProperty("refresh_token")
    private String refreshToken;


}
