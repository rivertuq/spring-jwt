package ru.ostritsov.shop.spring_jwt.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import ru.ostritsov.shop.spring_jwt.model.Token;
import ru.ostritsov.shop.spring_jwt.repositories.TokenRepository;

@Component
@AllArgsConstructor
public class CustomLogoutHandler implements LogoutHandler {

    private final TokenRepository tokenRepository;
    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {

        String authHeader = request.getHeader("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        String token = authHeader.substring(7);

        Token storedToken = tokenRepository.findByAccessToken(token).orElse(null);

        if (token != null) {
            storedToken.setLoggedOut(true);
            tokenRepository.save(storedToken);
        }

    }
}
