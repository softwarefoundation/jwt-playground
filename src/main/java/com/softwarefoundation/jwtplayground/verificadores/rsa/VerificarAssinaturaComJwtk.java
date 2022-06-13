package com.softwarefoundation.jwtplayground.verificadores.rsa;

import com.softwarefoundation.jwtplayground.util.Certificado;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public class VerificarAssinaturaComJwtk {

    /**
     * Arquivo .txt com token
     */
    private static final Path PATH_JWT = Paths.get("");

    public static void main(String[] args) throws Exception {

        String jws = new String(Files.readAllBytes(PATH_JWT));

        Jws<Claims> claims = Jwts.parser()
                .setSigningKey(Certificado.getInstancePublicKeyRSA())
                .parseClaimsJws(jws);

        log.info("ISS: {}", new String(claims.getBody().getIssuer().getBytes(StandardCharsets.UTF_8)));
    }

}
