package main

import "core:crypto/hash"

digit_check :: proc(payload: []byte, digest: []byte) -> bool {
	hash.hash(hash.Algorithm.SHA256, payload, digest)
    // first 3 bytes == 0  ->  6 leading hex digits
    return digest[0] == 0 && digest[1] == 0 && digest[2] == 0
}

@(export)
solver :: proc(challenge: u32) -> u32 {
	parts := [2]u32{challenge, 0}
	digest: [32]byte

	for nonce: u32 = 0;; nonce += 1 {
		parts[1] = nonce
		payload := transmute([8]byte)parts

        if digit_check(payload[:], digest[:]) {
        	return nonce
        }
	}
}
