package main

import "core:fmt"
import "core:crypto"
import "core:crypto/hash"
import "core:crypto/hmac"

SECRET_KEY : [32]byte

Evaluation :: enum{Pass, Fail, Timeout}

sign :: proc(challenge, ip_address, time_stamp: u32) -> [32]byte {
	parts := [3]u32{challenge, ip_address, time_stamp}
	msg   := transmute([12]byte)parts
	signature: [32]byte

	hmac.sum(hash.Algorithm.SHA512_256, signature[:], msg[:], SECRET_KEY[:])
	return signature
}

authenticate :: proc(signature: []byte, challenge, ip_address, time_stamp: u32) -> bool {
	parts := [3]u32{challenge, ip_address, time_stamp}
    msg   := transmute([12]byte)parts

    return hmac.verify(hash.Algorithm.SHA512_256, signature[:], msg[:], SECRET_KEY[:])
}

digit_check :: proc(payload: []byte, digest: []byte) -> bool {
	hash.hash(hash.Algorithm.SHA512_256, payload, digest)
    // first 3 bytes == 0  →  6 leading hex digits
    return digest[0] == 0 && digest[1] == 0 && digest[2] == 0
}

solver :: proc(challenge: u32) -> (u32, u32) {
	parts := [2]u32{challenge, 0}
	digest: [32]byte

	for nonce: u32 = 0;; nonce += 1 {
		parts[1] = nonce
		payload := transmute([8]byte)parts

        if digit_check(payload[:], digest[:]) {
        	fmt.println(digest)
        	return challenge, nonce
        }
	}
}

verifier :: proc(signature: []byte, challenge, nonce, ip_address, time_stamp: u32) -> Evaluation{
	if !authenticate(signature[:], challenge, ip_address, time_stamp) {
		fmt.println("failed to authenticate")
		return Evaluation.Fail
	}

	result: Evaluation

	payload: [8]byte
	digest: [32]byte

    payload = transmute([8]byte)[2]u32{challenge, nonce}

	result = digit_check(payload[:], digest[:]) ? .Pass : .Fail

	return result
}

main :: proc() {
	crypto.rand_bytes(SECRET_KEY[:])

	ip_address : u32 = 0
	time_stamp : u32 = 0

	challenge_bytes : [4]byte
	crypto.rand_bytes(challenge_bytes[:])
	challenge := transmute(u32)challenge_bytes

	sig := sign(challenge, ip_address, time_stamp)

	fmt.println("signature: ", sig)

	_, nonce := solver(challenge)
	fmt.printfln("solved, nonce:%d", nonce)

	result := verifier(sig[:], challenge, nonce, ip_address, time_stamp)

	#partial switch result {
	case .Pass:
		fmt.println("passed")
	case .Fail:
		fmt.println("failed")
	case :
		fmt.println("something went wrong")
	}
}
