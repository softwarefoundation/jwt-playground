package com.softwarefoundation.jwtplayground.verificadores.ec;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.softwarefoundation.jwtplayground.util.Certificado;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public class VerificarAssinaturaECComNimbusJoseJwt {

    /**
     * Arquivo .txt com token
     */
    private static final Path PATH_JWT = Paths.get("");

    public static void main(String[] args) throws Exception {

        String jwt = new String(Files.readAllBytes(PATH_JWT));

        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSVerifier verifier = new ECDSAVerifier(Certificado.getInstancePublicKeyEC());
        boolean isAssinaturaVerificada = signedJWT.verify(verifier);


        log.info("Assinatura verificada: {}", isAssinaturaVerificada);

    }

}
