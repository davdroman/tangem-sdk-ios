import Foundation
import TangemSdk_secp256k1

extension Secp256k1Utils {
	func tweakPrivateKey(_ privateKey: Data, tweak: Data) throws -> Data {
		guard privateKey.count == 32 else {
			throw TangemSdkError.cryptoUtilsError("Private key size must be 32 bytes")
		}
		guard tweak.count == 32 else {
			throw TangemSdkError.cryptoUtilsError("Tweak size must be 32 bytes")
		}

		var privkey = privateKey.toBytes
		let tweakBytes = tweak.toBytes

		let result = secp256k1_ec_privkey_tweak_add(context, &privkey, tweakBytes)
		if result != 1 {
			throw TangemSdkError.cryptoUtilsError("Failed to tweak private key")
		}

		return Data(privkey)
	}
}
