package ru.iriyc.cstorage.service;

import com.google.common.io.BaseEncoding;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.iriyc.cstorage.crypto.AsymmetricUtil;
import ru.iriyc.cstorage.crypto.SymmetricUtil;
import ru.iriyc.cstorage.entity.ReferenceStream;
import ru.iriyc.cstorage.entity.Stream;
import ru.iriyc.cstorage.entity.User;
import ru.iriyc.cstorage.repository.ReferenceStreamRepository;
import ru.iriyc.cstorage.repository.StreamRepository;
import ru.iriyc.cstorage.service.api.StreamService;
import ru.iriyc.cstorage.service.api.TokenService;

import javax.annotation.PostConstruct;
import java.io.*;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;
import java.util.stream.Collectors;


@Service("streamService.v1")
@Slf4j
final class StreamServiceImpl implements StreamService {

    private static final File outputDirectory = new File(".secret");

    private final TokenService service;
    private final ReferenceStreamRepository referenceStreamRepository;
    private final StreamRepository streamRepository;

    @Autowired
    public StreamServiceImpl(@Qualifier("tokenService.v1") TokenService service,
                             @Qualifier("referenceStreamRepository.v1") ReferenceStreamRepository referenceStreamRepository,
                             @Qualifier("streamRepository.v1") StreamRepository streamRepository) {
        this.service = service;
        this.referenceStreamRepository = referenceStreamRepository;
        this.streamRepository = streamRepository;
    }

    @PostConstruct
    private void construct() {
        if (!outputDirectory.exists()) {
            log.debug("Create output directory: {}", outputDirectory.mkdirs());
        }
    }

    private static File file(String hash) {
        final String fileName = hash.toUpperCase();
        //Hashing.sha256().hashBytes(hash.getBytes(Charsets.UTF_8)).toString().toUpperCase();
        return new File(outputDirectory, fileName);
    }

    @Transactional
    @Override
    public void store(Stream stream, InputStream inputStream, String token) {
        final AsymmetricUtil.Keys keys = service.getKeys(token);
        final User user = service.getUser(token);
        try {
            final byte[] privateKey = SymmetricUtil.generatePrivateKey();
            final byte[] encryptedSecretKey = AsymmetricUtil.encrypt(keys.publicKey, privateKey);
            try (final OutputStream output = new FileOutputStream(file(stream.getHash()))) {
                final String hash = SymmetricUtil.encrypt(privateKey, inputStream, output);
                if (!hash.equalsIgnoreCase(stream.getHash()))
                    throw new RuntimeException("Hash не совпадает");
            }
            log.info("Store. PrivateKey: {}", BaseEncoding.base64().encode(privateKey));
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
    public InputStream stream(Stream stream, String token) {
        final AsymmetricUtil.Keys keys = service.getKeys(token);
        final ReferenceStream reference = referenceStreamRepository.find(stream, service.getUser(token));
        if (reference == null)
            throw new RuntimeException("Ссылка на поток не найдена");
        final byte[] encryptedSecretKey = BaseEncoding.base64().decode(reference.getSecretKey());
        try {
            final byte[] decryptSecretKey = AsymmetricUtil.decrypt(keys.privateKey, encryptedSecretKey);
            log.info("Load.  PrivateKey: {}", BaseEncoding.base64().encode(decryptSecretKey));
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                final File file = file(stream.getHash());
                try (InputStream inputStream = new FileInputStream(file)) {
                    SymmetricUtil.decrypt(decryptSecretKey, inputStream, outputStream);
                    return new ByteArrayInputStream(outputStream.toByteArray());
                }
            }
        } catch (Exception e) {
            log.error("", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void link(String token, Stream stream, User linkTo) throws InvalidKeySpecException {
        final AsymmetricUtil.Keys keys = service.getKeys(token);
        final PublicKey publicKey = service.getKeys(linkTo);
        final User owner = service.getUser(token);
        final ReferenceStream streamReference = referenceStreamRepository.find(stream, owner);

        final byte[] encryptedSecretKey;
        try {
            final byte[] encryptedOwnerSecretKey = BaseEncoding.base64().decode(streamReference.getSecretKey());
            final byte[] decryptSecretKey = AsymmetricUtil.decrypt(keys.privateKey, encryptedOwnerSecretKey);
            log.info("Load.  PrivateKey: {}", BaseEncoding.base64().encode(decryptSecretKey));
            encryptedSecretKey = AsymmetricUtil.encrypt(publicKey, decryptSecretKey);
        } catch (Exception e) {
            log.error("", e);
            throw new RuntimeException(e);
        }
        final ReferenceStream reference = new ReferenceStream();
        reference.setOwner(linkTo);
        reference.setStream(stream);
        reference.setSecretKey(BaseEncoding.base64().encode(encryptedSecretKey));
            /* FIXME: Установить виртуальную папку */
        reference.setDirectory(outputDirectory.getAbsolutePath());
        referenceStreamRepository.save(reference);
    }

    @Override
    public Set<Stream> list(User owner) {
        return referenceStreamRepository.list(owner).stream().map((referenceStream ->
                streamRepository.findOne(referenceStream.getStream().getId()))).collect(Collectors.toSet());
    }
}
