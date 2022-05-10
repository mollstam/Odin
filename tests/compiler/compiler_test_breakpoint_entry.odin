//+build ignore
// build flags: -debug -o:minimal
package test_compiler

// command: run
// command: image lookup --address $pc
// check: compiler_test_breakpoint_entry.odin:9

main :: proc() { // breakpoint
}