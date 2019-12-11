import Foundation

public struct Kit {

    public static func sign(data: Data, privateKey: Data) throws -> Data {
        precondition(data.count > 0, "Data must be non-zero size")
        precondition(privateKey.count > 0, "PrivateKey must be non-zero size")

        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        let status = data.withUnsafeBytes { ptr in
            privateKey.withUnsafeBytes { secp256k1_ecdsa_sign(ctx, signature, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), $0.baseAddress!.assumingMemoryBound(to: UInt8.self), nil, nil) }
        }
        guard status == 1 else { throw SignError.signFailed }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        var length: size_t = 128
        var der = Data(count: length)
        guard der.withUnsafeMutableBytes({ return secp256k1_ecdsa_signature_serialize_der(ctx, $0.baseAddress!.assumingMemoryBound(to: UInt8.self), &length, normalizedsig) }) == 1 else { throw SignError.noEnoughSpace }
        der.count = length

        return der
    }

    public static func compactSign(_ data: Data, privateKey: Data) throws -> Data {
        precondition(data.count > 0, "Data must be non-zero size")
        precondition(privateKey.count > 0, "PrivateKey must be non-zero size")

        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signature.deallocate() }
        let status = data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
            privateKey.withUnsafeBytes { secp256k1_ecdsa_sign(ctx, signature, ptr, $0, nil, nil) }
        }
        guard status == 1 else { throw SignError.signFailed }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { normalizedsig.deallocate() }
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        let length: size_t = 64
        var compact = Data(count: length)
        guard compact.withUnsafeMutableBytes({ return secp256k1_ecdsa_signature_serialize_compact(ctx, $0, normalizedsig) }) == 1 else { throw SignError.noEnoughSpace }
        compact.count = length

        return compact
    }

    public static func createPublicKey(fromPrivateKeyData privateKeyData: Data, compressed: Bool = false) -> Data {
        precondition(privateKeyData.count > 0, "PrivateKeyData must be non-zero size")
        // Convert Data to byte Array
        let privateKey = privateKeyData.withUnsafeBytes {
            [UInt8](UnsafeBufferPointer(start: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: privateKeyData.count))
        }

        // Create signing context
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        // Create public key from private key
        var c_publicKey: secp256k1_pubkey = secp256k1_pubkey()
        let result = secp256k1_ec_pubkey_create(
                ctx,
                &c_publicKey,
                UnsafePointer<UInt8>(privateKey)
        )

        // Serialise public key data into byte array (see header docs for secp256k1_pubkey)
        let keySize = compressed ? 33 : 65
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: keySize)
        let outputLen = UnsafeMutablePointer<Int>.allocate(capacity: 1)
        defer {
            output.deallocate()
            outputLen.deallocate()
        }
        outputLen.initialize(to: keySize)
        secp256k1_ec_pubkey_serialize(ctx, output, outputLen, &c_publicKey, UInt32(compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))
        let publicKey = [UInt8](UnsafeBufferPointer(start: output, count: keySize))

        return Data(publicKey)
    }


    public static func ellipticSign(_ hash: Data, privateKey: Data) throws -> Data {
        let encrypter = EllipticCurveEncrypterSecp256k1()
        guard var signatureInInternalFormat = encrypter.sign(hash: hash, privateKey: privateKey) else {
            throw SignError.signFailed
        }
        return encrypter.export(signature: &signatureInInternalFormat)
    }

    public static func ellipticIsValid(signature: Data, of hash: Data, publicKey: Data, compressed: Bool) -> Bool {
        guard let recoveredPublicKey = self.ellipticPublicKey(signature: signature, of: hash, compressed: compressed) else { return false }
        return recoveredPublicKey == publicKey
    }

    public static func ellipticPublicKey(signature: Data, of hash: Data, compressed: Bool) -> Data? {
        let encrypter = EllipticCurveEncrypterSecp256k1()
        var signatureInInternalFormat = encrypter.import(signature: signature)
        guard var publicKeyInInternalFormat = encrypter.publicKey(signature: &signatureInInternalFormat, hash: hash) else { return nil }
        return encrypter.export(publicKey: &publicKeyInInternalFormat, compressed: compressed)
    }


}
