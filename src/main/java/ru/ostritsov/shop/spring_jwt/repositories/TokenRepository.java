package ru.ostritsov.shop.spring_jwt.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import ru.ostritsov.shop.spring_jwt.model.Token;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {


    @Query("""
                    select t from Token t inner join User u
                    on t.user.id = u.id
                    where t.user.id = :userId and t.loggedOut = false
            """)
    List<Token> findAllAccessTokenByUser(Integer userId);

    Optional<Token> findByAccessToken(String token);

    Optional<Token> findByRefreshToken(String token);

}
