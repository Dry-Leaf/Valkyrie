package main

import "core:fmt"
import "core:strings"
import "core:log"
import "core:net"
import "core:time"
import "core:strconv"
import "core:encoding/hex"

import http "http"

listen :: proc() {
	context.logger = log.create_console_logger(.Info)

	s: http.Server
	http.server_shutdown_on_interrupt(&s)

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.route_get(&router, "/cookies", http.handler(cookies))
	http.route_get(&router, "/ping", http.handler(second))
	http.route_get(&router, "/", http.handler(index))

	http.route_get(&router, "/challenge", http.handler(get_challenge))

	// Matches every get request that did not match another route.
	http.route_get(&router, "(.*)", http.handler(static))

	http.route_post(&router, "/ping", http.handler(post_ping))

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

    fmt.printfln("signature: %x", sig)
    fmt.printfln("challenge: %x", challenge)
    fmt.printfln("time_stamp: %x", time_stamp)

    sig_str := string(hex.encode(sig[:]))

    buf1: [8]byte
    challenge_str := strconv.write_uint(buf1[:], u64(challenge), 16)

    buf2: [16]byte
    ts_str := strconv.write_int(buf2[:], time_stamp, 16)

    http.headers_set(&res.headers, "signature", sig_str)
    http.headers_set(&res.headers, "challenge", challenge_str)
    http.headers_set(&res.headers, "time_stamp", ts_str)

	http.redirect(res, "/")
}

cookies :: proc(req: ^http.Request, res: ^http.Response) {
	append(
		&res.cookies,
		http.Cookie{
			name         = "Session",
			value        = "123",
			expires_gmt  = time.now(),
			max_age_secs = 10,
			http_only    = true,
			same_site    = .Lax,
		},
	)
	http.respond_plain(res, "Yo!")
}

second :: proc(req: ^http.Request, res: ^http.Response) {
	//http.respond_plain(res, "pong")
	log.info("redirect attempt")
	http.redirect(res, "/second_test.html")
}

index :: proc(req: ^http.Request, res: ^http.Response) {
	http.respond_file(res, "static/index.html")
}

static :: proc(req: ^http.Request, res: ^http.Response) {
	http.respond_dir(res, "/", "static", req.url_params[0])
}

post_ping :: proc(req: ^http.Request, res: ^http.Response) {
	http.body(req, len("ping"), res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
		res := cast(^http.Response)res

		if err != nil {
			http.respond(res, http.body_error_status(err))
			return
		}

		if body != "ping" {
			http.respond(res, http.Status.Unprocessable_Content)
			return
		}

		http.respond_plain(res, "pong")
	})
}
