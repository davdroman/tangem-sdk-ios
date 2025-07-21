import CryptoKit
import Foundation
import TangemSdk_secp256k1

extension ExtendedPrivateKey {
	/// Derive an extended private key for the given derivation path (BIP44 style).
	/// - Parameter path: The derivation path (e.g. m/44'/111111'/0'/0/0).
	/// - Returns: The derived ExtendedPrivateKey at the end of the path.
	public func deriveChildPrivateKey(path: DerivationPath) throws -> ExtendedPrivateKey {
		var currentKey = self
		// Iterate through each level of the derivation path
		for node in path.nodes {  // assuming `nodes` gives indices with hardness info
			currentKey = try currentKey.deriveChildPrivateKey(index: node.index, hardened: node.isHardened)
		}
		return currentKey
	}

	/// Derive a child extended private key for a single index.
	private func deriveChildPrivateKey(index: UInt32, hardened: Bool) throws -> ExtendedPrivateKey {
		let parentPrivKey = self.privateKey

		// 1. Prepare data for HMAC-SHA512 (per BIP-32 specification):
		var data = Data()
		if hardened {
			// Hardened: 0x00 + parent private key (32 bytes)
			data.append(0x00)
			data.append(parentPrivKey)  // parentPrivKey is Data (32 bytes)
		} else {
			// Non-hardened: use parent *public* key in compressed form (33 bytes)
			let parentPubKey: Data = try Secp256k1Utils().createPublicKey(privateKey: parentPrivKey, compressed: true)
			data.append(parentPubKey)
		}
		// Append the 4-byte child index (big-endian). For hardened, index has 0x80000000 bit set.
		let childIndex: UInt32 = hardened ? (0x80000000 | index) : index
		var indexBE = childIndex.bigEndian
		data.append(Data(bytes: &indexBE, count: MemoryLayout<UInt32>.size))

		// 2. Compute HMAC-SHA512 with parent chain code as key and `data` as message:
		// (Using CryptoKit for HMAC-SHA512; alternatively use CommonCrypto or SDK's HMAC utility)
		let hmac = HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: self.chainCode))
		let I = Data(hmac)  // 64 bytes
		let IL = I.prefix(32)    // Left 32 bytes
		let IR = I.suffix(32)    // Right 32 bytes

		// 3. Derive child private key: childPriv = (IL + parentPriv) mod n
		// Use secp256k1 to add scalars mod curve order, which also checks for invalid results.
		// Use secp256k1 native function to tweak-add the private key:
		let childPrivKey = try Secp256k1Utils().tweakPrivateKey(parentPrivKey, tweak: IL)  // 32-byte derived private key
		let childChainCode = Data(IR)                                                      // 32-byte new chain code

		// 4. Compute parent fingerprint (first 4 bytes of HASH160 of parent *public* key):
		let parentPubKey: Data = try Secp256k1Utils().createPublicKey(privateKey: parentPrivKey, compressed: true)
		let parentHash160 = parentPubKey.sha256Ripemd160 // 20-byte HASH160
		let fingerprintBytes = parentHash160.prefix(4)

		// 5. Create the child extended private key with incremented depth
		return try ExtendedPrivateKey(
			privateKey: childPrivKey,
			chainCode: childChainCode,
			depth: self.depth + 1,
			parentFingerprint: Data(fingerprintBytes),
			childNumber: childIndex
		)
	}
}
