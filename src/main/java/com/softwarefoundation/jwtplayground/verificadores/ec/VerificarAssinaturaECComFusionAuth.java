package com.softwarefoundation.jwtplayground.verificadores.ec;

import com.softwarefoundation.jwtplayground.util.Certificado;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.ec.ECVerifier;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;

@Slf4j
public class VerificarAssinaturaECComFusionAuth {


    /**
     * Arquivo .txt com token
     */
    private static final Path PATH_JWT = Paths.get("");

    public static void main(String[] args) throws Exception {

        String jwt = new String(Files.readAllBytes(PATH_JWT));

        Verifier verifier = ECVerifier.newVerifier(Certificado.getInstancePublicKeyEC());

        JWT jwtDecoder = JWT.getDecoder().decode(jwt, verifier);

        log.info("ISS: {}", new String(jwtDecoder.issuer.getBytes(StandardCharsets.UTF_8)));

    }

}
