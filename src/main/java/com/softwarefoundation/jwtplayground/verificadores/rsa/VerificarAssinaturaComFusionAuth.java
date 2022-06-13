package com.softwarefoundation.jwtplayground.verificadores.rsa;

import com.softwarefoundation.jwtplayground.util.Certificado;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSAVerifier;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;

@Slf4j
public class VerificarAssinaturaComFusionAuth {
    /**
     * Arquivo .txt com token
     */
    private static final Path PATH_JWT = Paths.get("");

    public static void main(String[] args) throws Exception {

        String jwt = new String(Files.readAllBytes(PATH_JWT));

        Verifier verifier = RSAVerifier.newVerifier(Certificado.getInstancePublicKeyRSA());

        JWT jwtDecoder = JWT.getDecoder().decode(jwt, verifier);

        log.info("ISS: {}", new String(jwtDecoder.issuer.getBytes(StandardCharsets.UTF_8)));

    }

}
