//+build ignore
// build flags: -debug -o:minimal
package test_compiler

// command: run
// command: image lookup --address $pc
// check: compiler_test_debug_symbols.odin:17
// command: si
// command: image lookup --address $pc
// check: compiler_test_debug_symbols.odin:17
// command: si
// command: image lookup --address $pc
// check: compiler_test_debug_symbols.odin:17

main :: proc() {
	should_loop := true
	for should_loop { // breakpoint
	}
}