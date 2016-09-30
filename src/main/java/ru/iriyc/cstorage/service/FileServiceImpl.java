package ru.iriyc.cstorage.service;

import com.google.common.io.BaseEncoding;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.crypto.SymmetricUtil;
import ru.iriyc.cstorage.entity.ReferenceStream;
import ru.iriyc.cstorage.entity.SecretStream;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.ReferenceStreamRepository;
import ru.iriyc.cstorage.service.api.FileService;
import ru.iriyc.cstorage.service.api.TokenService;

import javax.annotation.PostConstruct;
import java.io.*;


@Service("fileService.v1")
@Slf4j
final class FileServiceImpl implements FileService {

    private static final File outputDirectory = new File("secret");

    @Autowired
    private TokenService service;

    @Autowired
    private ReferenceStreamRepository referenceStreamRepository;

    @PostConstruct
    private void construct() {
        if (!outputDirectory.exists()) {
            log.debug("Create output directory: {}", outputDirectory.mkdirs());
        }
    }

    @Override
    public void store(SecretStream stream, InputStream inputStream, String token) {
        final AsymmetricUtil.Keys keys = service.getKeys(token);
        final User user = service.getUser(token);
        try {
            final byte[] privateKey = SymmetricUtil.generatePrivateKey();
            final byte[] encryptedSecretKey = AsymmetricUtil.encrypt(keys.publicKey, privateKey);
            final ReferenceStream reference = new ReferenceStream();
            reference.setOwner(user);
            reference.setStream(stream);
            reference.setSecretKey(BaseEncoding.base64().encode(encryptedSecretKey));
            /* FIXME: Установить виртуальную папку */
            reference.setDirectory(outputDirectory.getAbsolutePath());
            referenceStreamRepository.save(reference);
        } catch (Exception e) {
            log.error("", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * FIXME: Переписать
     */
    @Override
    public InputStream stream(SecretStream stream, String token) {
        final AsymmetricUtil.Keys keys = service.getKeys(token);
        final ReferenceStream reference = referenceStreamRepository.find(stream, service.getUser(token));
        if (reference == null)
            throw new RuntimeException("Ссылка на поток не найдена");
        final byte[] encryptedSecretKey = BaseEncoding.base64().decode(reference.getSecretKey());
        try {
            final byte[] decryptSecretKey = AsymmetricUtil.decrypt(keys.privateKey, encryptedSecretKey);
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                try (InputStream inputStream = new FileInputStream(new File(outputDirectory, stream.getHash()))) {
                    SymmetricUtil.decrypt(decryptSecretKey, inputStream, outputStream);
                    return new ByteArrayInputStream(outputStream.toByteArray());
                }
            }
        } catch (Exception e) {
            log.error("", e);
            throw new RuntimeException(e);
        }
    }
}
