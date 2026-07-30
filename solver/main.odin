#+build !freestanding
package main

import "core:flags"
import "core:os"
import "core:fmt"

main :: proc() {
	Options :: struct {
		challenge: u32 `args:"required" usage:"The given PoW challenge to solve."`
	}

	opt: Options
	style : flags.Parsing_Style = .Odin

	flags.parse_or_exit(&opt, os.args, style)

	nonce := solver(opt.challenge)

	fmt.println(nonce)
}
