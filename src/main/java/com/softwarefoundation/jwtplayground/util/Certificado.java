package com.softwarefoundation.jwtplayground.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Certificado {

    /**
     * Arquivo .cer ou .pem
     */
    public static final Path PATH_CERTIFICADO_RSA = Paths.get("");
    public static final Path PATH_CERTIFICADO_EC = Paths.get("");

    /**
     * Com algoritmo de RSA.
     *
     * @return
     * @throws Exception
     */
    private static Certificate getInstance() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return certificateFactory.generateCertificate(Files.newInputStream(PATH_CERTIFICADO_RSA, StandardOpenOption.READ));
    }

    public static RSAPublicKey getInstancePublicKeyRSA() throws Exception {
        return (RSAPublicKey) getInstance().getPublicKey();
    }


    /**
     * Com algoritmo de Curva Elíptica.
     *
     * @return
     */
    public static ECPublicKey getInstancePublicKeyEC() {
        Security.addProvider(new BouncyCastleProvider());
        PublicKey publicKey = null;
        try (Reader keyReader = new FileReader(PATH_CERTIFICADO_EC.toFile());
             PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            KeyFactory factory = KeyFactory.getInstance("EC");
            publicKey = factory.generatePublic(pubKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (ECPublicKey) publicKey;
    }


    private static Path getPath(final String nomeArquivo) throws FileNotFoundException {
       return ResourceUtils.getFile("classpath:certificado-rsa.cer").toPath();
    }


}
