package com.softwarefoundation.jwtplayground.verificadores.rsa;

import com.softwarefoundation.jwtplayground.util.Certificado;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;

@Slf4j
public class VerificarAssinaturaComJose4J {
    /**
     * Arquivo .txt com token
     */
    private static final Path PATH_JWT = Paths.get("");

    public static void main(String[] args) throws Exception {

        String jwt = new String(Files.readAllBytes(PATH_JWT));

        JsonWebSignature jws = new JsonWebSignature();

        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256));

        jws.setCompactSerialization(jwt);

        jws.setKey(Certificado.getInstancePublicKeyRSA());

        boolean isAssinaturaVerificada = jws.verifySignature();
        log.info("Assinatura verificada: {}", isAssinaturaVerificada);

    }

}
