package main

import "core:fmt"
import "core:crypto"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:time"

Evaluation :: enum{Pass, Fail, Timeout}

Message :: struct #packed {
       challenge:  u32,
       ip_address: u32,
       time_stamp: i64,
   }

TIMEOUT :: time.Minute * 2

SECRET_KEY : [32]byte

pack_msg :: proc(challenge, ip_address: u32, time_stamp: i64) -> [16]byte {
    return transmute([16]byte)Message{challenge, ip_address, time_stamp}
}

sign :: proc(challenge, ip_address: u32, time_stamp: i64) -> [32]byte {
    msg := pack_msg(challenge, ip_address, time_stamp)
    signature: [32]byte

	hmac.sum(hash.Algorithm.SHA512_256, signature[:], msg[:], SECRET_KEY[:])
	return signature
}

authenticate :: proc(signature: []byte, challenge, ip_address: u32, issue_ts: i64) -> bool {
	msg := pack_msg(challenge, ip_address, issue_ts)
    return hmac.verify(hash.Algorithm.SHA512_256, signature[:], msg[:], SECRET_KEY[:])
}

digit_check :: proc(payload: []byte, digest: []byte) -> bool {
	hash.hash(hash.Algorithm.SHA512_256, payload, digest)
    // first 3 bytes == 0  ->  6 leading hex digits
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

verifier :: proc(signature: []byte, challenge, nonce, ip_address: u32, issue_ts: i64) -> Evaluation{
	if !authenticate(signature[:], challenge, ip_address, issue_ts) {
		fmt.println("failed to authenticate")
		return .Fail
	}

	submission_ts := time.time_to_unix(time.now())
	duration := time.diff(time.unix(issue_ts, 0), time.unix(submission_ts, 0))

	fmt.println("Duration: ", time.duration_seconds(duration))

	if duration > TIMEOUT {
        return .Timeout
    }

	result: Evaluation

	payload: [8]byte
	digest: [32]byte

    payload = transmute([8]byte)[2]u32{challenge, nonce}

	result = digit_check(payload[:], digest[:]) ? .Pass : .Fail

	return result
}

issue_challenge :: proc(ip_address: u32) -> ([32]byte, u32, i64) {
	time_stamp := time.time_to_unix(time.now())

	challenge_bytes : [4]byte
	crypto.rand_bytes(challenge_bytes[:])
	challenge := transmute(u32)challenge_bytes

	sig := sign(challenge, ip_address, time_stamp)

	return sig, challenge, time_stamp
}

main :: proc() {
	// crypto.rand_bytes(SECRET_KEY[:])

	// ip_address : u32 = 0

	// sig, challenge, time_stamp := issue_challenge(ip_address)

	// _, nonce := solver(challenge)
	// fmt.printfln("solved, nonce:%d", nonce)

	// result := verifier(sig[:], challenge, nonce, ip_address, time_stamp)

	// switch result {
	// case .Pass:
	// 	fmt.println("passed")
	// case .Fail:
	// 	fmt.println("failed")
	// case .Timeout :
	// 	fmt.println("timed out")
	// }
	listen()
}
