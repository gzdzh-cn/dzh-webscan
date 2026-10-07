// Heuristics, not proof of maliciousness. Results require manual review.
rule PHP_Dynamic_Execution_Input {
  strings:
    $exec = /\b(eval|assert)\s*\(/ nocase
    $input = /\$_(POST|GET|REQUEST|COOKIE)\s*\[/
  condition: filesize < 20MB and all of them
}
rule PHP_Encoded_Eval {
  strings:
    $eval = /\beval\s*\(/ nocase
    $decode = /\b(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/ nocase
  condition: filesize < 20MB and all of them
}
rule PHP_Command_Input {
  strings:
    $exec = /\b(system|shell_exec|passthru|exec|popen|proc_open)\s*\(/ nocase
    $input = /\$_(POST|GET|REQUEST|COOKIE)\s*\[/
  condition: filesize < 20MB and all of them
}
