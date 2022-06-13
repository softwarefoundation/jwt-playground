package com.softwarefoundation.jwtplayground.verificadores.ec;

import com.softwarefoundation.jwtplayground.util.Certificado;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public class VerificarAssinaturaECComJose4J {
    /**
     * Arquivo .txt com token
     */
    private static final Path PATH_JWT = Paths.get("");

    public static void main(String[] args) throws Exception {

        String jwt = new String(Files.readAllBytes(PATH_JWT));

        JsonWebSignature jws = new JsonWebSignature();

        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512));

        jws.setCompactSerialization(jwt);

        jws.setKey(Certificado.getInstancePublicKeyEC());

        boolean isAssinaturaVerificada = jws.verifySignature();
        log.info("Assinatura verificada: {}", isAssinaturaVerificada);

    }

}
