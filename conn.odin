package main

import "core:fmt"
import "core:log"
import "core:net"
import "core:strconv"
import "core:encoding/hex"

import http "http"

index_html :: #load("static/index.html.gz")

listen :: proc() {
	context.logger = log.create_console_logger(.Info)

	s: http.Server
	http.server_shutdown_on_interrupt(&s)

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.route_get(&router, "/", http.handler(index))
	http.route_get(&router, "/challenge", http.handler(get_challenge))
	http.route_get(&router, "/verify", http.handler(get_verification))
	http.route_get(&router, "/authenticate", http.handler(get_challenge))

	// Matches every get request that did not match another route.
	http.route_get(&router, "(.*)", http.handler(static))

	routed := http.router_handler(&router)

	log.info("Listening on http://localhost:6969")

	err := http.listen_and_serve(&s, routed, net.Endpoint{address = net.IP4_Loopback, port = 6969})
	fmt.assertf(err == nil, "server stopped with error: %v", err)
}

get_challenge :: proc (req: ^http.Request, res: ^http.Response) {
	ip_address : u128

  	ip_address_str, present := http.headers_get(req.headers, "X-Real-IP")
   	if present {
    	ok : bool
    	ip_address, ok = strconv.parse_u128_of_base(ip_address_str, 16)
     	fmt.assertf(ok, "client ip could not be parsed")
    } else {
    	ip_address = 0
    }

    sig, challenge, time_stamp := issue_challenge(ip_address)

    sig_str := string(hex.encode(sig[:], context.temp_allocator))

    buf1: [8]byte
    challenge_str := strconv.write_uint(buf1[:], u64(challenge), 16)

    buf2: [16]byte
    ts_str := strconv.write_int(buf2[:], time_stamp, 16)

    notif := fmt.tprintf("signature: %s\nchallenge: %s\ntime_stamp: %s", sig_str, challenge_str, ts_str)
    defer free_all(context.temp_allocator)

    http.headers_set(&res.headers, "signature", sig_str)
    http.headers_set(&res.headers, "challenge", challenge_str)
    http.headers_set(&res.headers, "time_stamp", ts_str)

    http.respond_plain(res, notif)
}

get_verification :: proc(req: ^http.Request, res: ^http.Response) {
	signature, ok, _ := http.query_get_bytes(req.url, "signature")
	if !ok {
		http.respond_plain(res, "not all params present")
		return
	}

	challenge, ok1, _ := http.query_get_uint(req.url, "challenge")
	if !ok1 {
		http.respond_plain(res, "not all params present")
		return
	}

	nonce, ok2, _ := http.query_get_uint(req.url, "nonce")
	if !ok2 {
		http.respond_plain(res, "not all params present")
		return
	}

	time_stamp, ok3, _ := http.query_get_int(req.url, "time_stamp")
	if !ok3 {
		http.respond_plain(res, "not all params present")
		return
	}

	ip_address : u128

  	ip_address_str, present := http.headers_get(req.headers, "X-Real-IP")
   	if present {
    	ok : bool
    	ip_address, ok = strconv.parse_u128_of_base(ip_address_str, 16)
     	fmt.assertf(ok, "client ip could not be parsed")
    } else {
    	ip_address = 0
    }

 	notif := fmt.tprintf("signature: %x\nchallenge: %x\ntime_stamp: %x", signature, challenge, time_stamp)
    defer free_all(context.temp_allocator)

    log.info(notif)

	eval := verifier(signature[:], u32(challenge), u32(nonce), ip_address, i64(time_stamp))
	eval_msg : string

	switch eval {
	case .Pass:
		eval_msg = "passed"
	case .Fail:
		eval_msg = "failed"
	case .Timeout :
		eval_msg = "timed out"
	}

	http.respond_plain(res, eval_msg)
}

index :: proc(req: ^http.Request, res: ^http.Response) {
	http.respond_file_content(res, "static/index.html.gz", index_html)
}

static :: proc(req: ^http.Request, res: ^http.Response) {
	http.respond_dir(res, "/", "static", req.url_params[0])
}
