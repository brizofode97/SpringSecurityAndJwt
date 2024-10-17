package com.openclassroom.SpringSecurityAndJWT.services;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class JwtService {

    private final JwtEncoder jwtEncoder;

    public JwtService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    //NOTE: Cette méthode est testé uniquement sur postman; le test sur swagger n'a pas marché
    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer("Self")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.DAYS))
                .subject(authentication.getName())
                .build();

        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), jwtClaimsSet);

        return jwtEncoder.encode(jwtEncoderParameters).getTokenValue();
    }

}
