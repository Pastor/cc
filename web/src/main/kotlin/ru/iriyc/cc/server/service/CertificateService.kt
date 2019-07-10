package ru.iriyc.cc.server.service

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import ru.iriyc.cc.server.Authority
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.FileWriter
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.*

internal object CertificateService {

    private const val PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private const val KEYGEN_ALGORITHM = "RSA"
    private const val SECURE_RANDOM_ALGORITHM = "SHA1PRNG"
    private const val SIGNATURE_ALGORITHM = "SHA1WithRSAEncryption"
    private const val ROOT_KEY_SIZE = 2048
    private val NOT_BEFORE = Date(System.currentTimeMillis() - 86400000L * 365)
    private val NOT_AFTER = Date(System.currentTimeMillis() + 86400000L * 365 * 100)

    internal fun initializeKeyStore(authority: Authority): File {
        val ksFile = authority.aliasFile(false)
        val pemFile = authority.aliasFile(true)
        if (!(ksFile.exists() && pemFile.exists())) {
            val keystore = createRootCertificate(authority, "PKCS12")
            FileOutputStream(ksFile).use { os -> keystore.store(os, authority.password) }
            val cert = keystore.getCertificate(authority.alias)
            exportPem(pemFile, cert)
        }
        return ksFile
    }

    private fun exportPem(exportFile: File, cert: Any) {
        FileWriter(exportFile).use { fw -> JcaPEMWriter(fw).use { pw -> pw.writeObject(cert) } }
    }

    private fun generateKeyPair(keySize: Int): KeyPair {
        val generator = KeyPairGenerator.getInstance(KEYGEN_ALGORITHM/* , PROVIDER_NAME */)
        val secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM/* , PROVIDER_NAME */)
        generator.initialize(keySize, secureRandom)
        return generator.generateKeyPair()
    }

    private fun createRootCertificate(authority: Authority,
                                      keyStoreType: String): KeyStore {
        val keyPair = generateKeyPair(ROOT_KEY_SIZE)

        val issuer = X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, authority.commonName)
                .addRDN(BCStyle.O, authority.organization)
                .addRDN(BCStyle.OU, authority.organizationalUnitName)
                .build()

        val serial = BigInteger.valueOf(initRandomSerial())
        val pubKey = keyPair.public

        val generator = JcaX509v3CertificateBuilder(issuer, serial, NOT_BEFORE, NOT_AFTER, issuer, pubKey)

        generator.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(pubKey))
        generator.addExtension(Extension.basicConstraints, true, BasicConstraints(true))

        val usage = KeyUsage(
                KeyUsage.keyCertSign or KeyUsage.digitalSignature or KeyUsage.keyEncipherment or KeyUsage.dataEncipherment or KeyUsage.cRLSign
        )
        generator.addExtension(Extension.keyUsage, false, usage)

        val purposes = ASN1EncodableVector()
        purposes.add(KeyPurposeId.id_kp_serverAuth)
        purposes.add(KeyPurposeId.id_kp_clientAuth)
        purposes.add(KeyPurposeId.anyExtendedKeyUsage)
        generator.addExtension(Extension.extendedKeyUsage, false, DERSequence(purposes))

        val cert = signCertificate(generator, keyPair.private)

        val result = KeyStore.getInstance(keyStoreType/* , PROVIDER_NAME */)
        result.load(null, null)
        result.setKeyEntry(authority.alias, keyPair.private, authority.password, arrayOf<Certificate>(cert))
        return result
    }

    private fun createSubjectKeyIdentifier(key: Key): SubjectKeyIdentifier {
        val bIn = ByteArrayInputStream(key.encoded)
        ASN1InputStream(bIn).use { `is` ->
            val seq = `is`.readObject() as ASN1Sequence
            val info = SubjectPublicKeyInfo.getInstance(seq)
            return BcX509ExtensionUtils().createSubjectKeyIdentifier(info)
        }
    }

    private fun signCertificate(certificateBuilder: X509v3CertificateBuilder,
                                signedWithPrivateKey: PrivateKey): X509Certificate {
        val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(signedWithPrivateKey)
        return JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer))
    }

    private fun initRandomSerial(): Long {
        val rnd = Random()
        // prevent browser certificate caches, cause of doubled serial numbers
        // using 48bit random number
        var sl = rnd.nextInt().toLong() shl 32 or ((rnd.nextInt() and 0xFFFFFFFFL.toInt()).toLong())
        // let reserve of 16 bit for increasing, serials have to be positive
        sl = sl and 0x0000FFFFFFFFFFFFL
        return sl
    }
}
