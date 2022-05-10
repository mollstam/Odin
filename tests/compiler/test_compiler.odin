package test_compiler

import "core:testing"
import tc "tests:common"

@test
test_compiler_debug_symbols :: proc(t: ^testing.T) {
	run_compiler_test(t, tc.get_data_path(t, "compiler/compiler_test_debug_symbols.odin"))
}

@test
test_compiler_breakpoint_entry :: proc(t: ^testing.T) {
	run_compiler_test(t, tc.get_data_path(t, "compiler/compiler_test_breakpoint_entry.odin"))
}



// ---
// should we put this in a different file / past of testing package?

import "core:c/libc"
import "core:fmt"
import "core:strings"
import "core:odin/ast"
import "core:odin/tokenizer"
import "core:odin/parser"
import "core:odin/printer"
import "core:os"
import "core:encoding/json"
import "core:runtime"
import "core:strconv"

build_flags_prefix :: "// build flags:"
command_prefix :: "// command:"
check_prefix :: "// check:"
breakpoint_token :: "// breakpoint"
output_dir :: "compiler/tmp"

Debugger_Output_Entry :: struct {
	command: string,
	output:  string,
}

Debugger_Output :: struct {
	entries: []Debugger_Output_Entry,
}

Check :: struct {
	predicate: string,
	loc: runtime.Source_Code_Location,
}

run_compiler_test :: proc(t: ^testing.T, filepath: string) {
	provided_build_flags : string
	breakpoints : [dynamic]tokenizer.Pos
	commands : [dynamic]string
	checks : [dynamic]Check

	tmp_dir := tc.get_data_path(t, output_dir)
	os.make_directory(tmp_dir, 511)

	parse_test_file(filepath, &provided_build_flags, &breakpoints, &commands, &checks)
	ok := build_test(t, filepath, provided_build_flags)
	testing.expect(t, ok, "test should build")

	run_compiler_test_lldb(t, breakpoints, commands, checks)
}

parse_test_file :: proc(filepath: string, out_build_flags: ^string, out_breakpoints: ^[dynamic]tokenizer.Pos, out_commands: ^[dynamic]string, out_checks: ^[dynamic]Check) {
	test_source_bytes, ok := os.read_entire_file(filepath)
	test_source := string(test_source_bytes)
	assert(ok, "test file could be read")

	p := parser.default_parser()
	file := ast.File {
		fullpath = filepath,
		src = test_source,
	}

	p.file = &file
	tokenizer.init(&p.tok, file.src, file.fullpath, p.err)
	for p.curr_tok.kind != .EOF {
		parser.advance_token(&p)
		if p.lead_comment == nil {
			continue
		}

		for t in p.lead_comment.list {
			if strings.has_prefix(t.text, build_flags_prefix) {
				out_build_flags^ = strings.cut(t.text, len(build_flags_prefix))
				out_build_flags^ = strings.trim_space(out_build_flags^)
			} else if t.text == breakpoint_token {
				append(out_breakpoints, t.pos)
			} else if strings.has_prefix(t.text, command_prefix) {
				cmd := strings.cut(t.text, len(command_prefix))
				cmd = strings.trim_space(cmd)
				append(out_commands, cmd)
			} else if strings.has_prefix(t.text, check_prefix) {
				predicate := strings.cut(t.text, len(check_prefix))
				predicate = strings.trim_space(predicate)
				check_index := len(out_checks^)
				check : Check
				check.predicate = predicate
				check.loc.file_path = t.pos.file
				check.loc.line = cast(i32)t.pos.line
				check.loc.column = cast(i32)t.pos.column
				append(out_checks, check)

				// embed a reference to the check into the command stream, so we can process the check at the correct point when running the script
				append(out_commands, fmt.tprintf("script -l python -- print(\"%s %d\")", check_prefix, check_index))
			}
		}
	}
}

get_output_path :: proc(t: ^testing.T, path: string) -> string {
	return tc.get_data_path(t, fmt.tprintf("%s/%s", output_dir, path))
}

build_test :: proc(t: ^testing.T, filepath: string, provided_build_flags: string) -> bool {
	build_command := fmt.tprintf("odin build %s -file %s -out:%s", filepath, provided_build_flags, get_output_path(t, "compiler_test.bin"))
	res := libc.system(strings.clone_to_cstring(build_command))
	return res == 0
}

run_compiler_test_lldb :: proc(t: ^testing.T, breakpoints: [dynamic]tokenizer.Pos, commands: [dynamic]string, checks: [dynamic]Check) {
	python_script_path := tc.get_data_path(t, "compiler/lldb_batchmode.py")
	script_filename := get_output_path(t, "lldb.script")
	script_builder := strings.make_builder()
	defer strings.destroy_builder(&script_builder)
	strings.write_string_builder(&script_builder, "settings set auto-confirm true\n")
	strings.write_string_builder(&script_builder, "version\n")
	strings.write_string_builder(&script_builder, fmt.tprintf("command script import %s\n", python_script_path))

	for bp in breakpoints {
		strings.write_string_builder(&script_builder, fmt.tprintf("breakpoint set --file %s --line %d\n", bp.file, bp.line))
	}

	for cmd in commands {
		strings.write_string_builder(&script_builder, fmt.tprintf("%s\n", cmd))
	}

	strings.write_string_builder(&script_builder, "quit\n")
	os.write_entire_file(script_filename, script_builder.buf[:])

	target_path := get_output_path(t, "compiler_test.bin")
	debugger_output_path := get_output_path(t, "debugger_command_output.json")
	python_command := fmt.tprintf("python %s %s %s %s", python_script_path, target_path, script_filename, debugger_output_path)
	testing.log(t, python_command)
	res := libc.system(strings.clone_to_cstring(python_command))
	exit_status := (res >> 8) & 0xff
	testing.expect(t, exit_status == 0, fmt.tprintf("exit status from '%s' should be 0, not %d", python_command, exit_status))

	ok: bool
	debugger_output_bytes: []u8
	debugger_output_bytes, ok = os.read_entire_file(debugger_output_path)
	testing.expect(t, ok, "file could be read")
	debugger_output: Debugger_Output
	err := json.unmarshal(debugger_output_bytes, &debugger_output, json.DEFAULT_SPECIFICATION)
	defer delete(debugger_output.entries)

	last_output: string
	for entry in debugger_output.entries {
		if strings.has_prefix(entry.output, check_prefix) {
			check_index_str := strings.cut(entry.output, len(check_prefix))
			check_index_str = strings.trim_space(check_index_str)
			check_index := strconv.atoi(check_index_str)
			check := checks[check_index]
			testing.expect(t, strings.contains(last_output, check.predicate), fmt.tprintf("Expected compiler output `%s` to match check `%s`\n", last_output, check.predicate), check.loc)
		}
		last_output = entry.output
	}
}
