package main

import "core:fmt"
import "core:math/rand"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:mem"
import "core:slice"

SECRET_KEY :: []u8{1,2,3}

Evaluation :: enum{Pass, Fail, Timeout}

digit_check :: proc(payload: []u8, digest: []u8) -> bool {
	hash.hash(hash.Algorithm.SHA512_256, payload, digest)
    // first 3 bytes == 0  →  6 leading hex digits
    return digest[0] == 0 && digest[1] == 0 && digest[2] == 0
}

solver :: proc(challenge: u32) -> (u32, u32) {
	parts := [2]u32{challenge, 0}
	digest: [32]u8

	for nonce: u32 = 0;; nonce += 1 {
		parts[1] = nonce
		payload := transmute([8]u8)parts

        if digit_check(payload[:], digest[:]) {
        	fmt.println(digest)
        	return challenge, nonce
        }
	}
}

authenticate :: proc(signature, challenge, ip_address, time_stamp: u32) -> bool {
	parts := [3]u32{challenge, ip_address, time_stamp}
    msg   := transmute([12]u8)parts
    sig   := transmute([4]u8)signature

    return hmac.verify(hash.Algorithm.SHA512_256, sig[:], msg[:], SECRET_KEY)
}

verifier :: proc(challenge, nonce: u32) -> Evaluation{
	result: Evaluation

	payload: [8]u8
	digest: [32]u8

    payload = transmute([8]u8)[2]u32{challenge, nonce}

	result = digit_check(payload[:], digest[:]) ? .Pass : .Fail

	return result
}

main :: proc() {
	challenge := rand.uint32()
	_, nonce := solver(challenge)
	fmt.printfln("solved, nonce:%d", nonce)
	result := verifier(challenge, nonce)

	#partial switch result {
	case .Pass:
		fmt.println("passed")
	case .Fail:
		fmt.println("failed")
	case :
		fmt.println("something went wrong")
	}
}
