package main

import "core:crypto"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:time"

Evaluation :: enum{Pass, Fail, Timeout}

Message :: struct #packed {
       challenge:  u32,
       ip_address: u128,
       time_stamp: i64,
   }

TIMEOUT :: time.Minute * 2

SECRET_KEY : [32]byte

pack_msg :: proc(challenge: u32, ip_address: u128, time_stamp: i64) -> [28]byte {
    return transmute([28]byte)Message{challenge, ip_address, time_stamp}
}

sign :: proc(challenge: u32, ip_address: u128, time_stamp: i64) -> [32]byte {
    msg := pack_msg(challenge, ip_address, time_stamp)
    signature: [32]byte

	hmac.sum(hash.Algorithm.SHA512_256, signature[:], msg[:], SECRET_KEY[:])
	return signature
}

authenticate :: proc(signature: []byte, challenge: u32, ip_address: u128, issue_ts: i64) -> bool {
	msg := pack_msg(challenge, ip_address, issue_ts)
    return hmac.verify(hash.Algorithm.SHA512_256, signature[:], msg[:], SECRET_KEY[:])
}

digit_check :: proc(payload: []byte, digest: []byte) -> bool {
	hash.hash(hash.Algorithm.SHA512_256, payload, digest)
    // first 3 bytes == 0  ->  6 leading hex digits
    return digest[0] == 0 && digest[1] == 0 && digest[2] == 0
}

verifier :: proc(signature: []byte, challenge, nonce: u32, ip_address: u128, issue_ts: i64) -> Evaluation{
	if !authenticate(signature[:], challenge, ip_address, issue_ts) {
		return .Fail
	}

	submission_ts := time.time_to_unix(time.now())
	duration := time.diff(time.unix(issue_ts, 0), time.unix(submission_ts, 0))

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

issue_challenge :: proc(ip_address: u128) -> ([32]byte, u32, i64) {
	time_stamp := time.time_to_unix(time.now())

	challenge_bytes : [4]byte
	crypto.rand_bytes(challenge_bytes[:])
	challenge := transmute(u32)challenge_bytes

	sig := sign(challenge, ip_address, time_stamp)

	return sig, challenge, time_stamp
}

main :: proc() {
	crypto.rand_bytes(SECRET_KEY[:])

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
