import re

def parse_c_code(code: str):
    # Remove comments (simplified)
    code_no_comments = re.sub(r'//.*?\n|/\*.*?\*/', '\n', code, flags=re.DOTALL)
    
    # 1. Includes & Dependencies
    includes = []
    dependencies = []
    for match in re.finditer(r'^\s*#include\s*(<|")([^>"]+)(>|")', code, re.MULTILINE):
        inc = match.group(2)
        includes.append(inc)
        if match.group(1) == '"':
            dependencies.append(inc)
            
    # 2. Function Definitions
    # Match return type, name, params.
    # Exclude keywords like if, for, while, switch, return
    func_pattern = re.compile(
        r'^\s*(?P<ret>[a-zA-Z_][\w\s\*:]+?)\s+(?P<name>[a-zA-Z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?P<body>\{|;)', 
        re.MULTILINE
    )
    
    definitions = []
    declarations = []
    
    lines = code.split('\n')
    
    def get_line(index):
        return code[:index].count('\n') + 1

    for match in func_pattern.finditer(code):
        ret_type = match.group('ret').strip()
        name = match.group('name')
        params_str = match.group('params').strip()
        body_start = match.group('body')
        
        # Skip control flow keywords that look like functions
        if name in ('if', 'for', 'while', 'switch', 'return', 'catch'):
            continue
            
        params = [p.strip() for p in params_str.split(',')] if params_str else []
        start_line = get_line(match.start())
        
        if body_start == ';':
            declarations.append({
                "name": name,
                "return_type": ret_type,
                "parameters": params,
                "line": start_line
            })
        else:
            # Find end of body by counting braces
            brace_count = 1
            idx = match.end()
            body_content = ""
            while idx < len(code) and brace_count > 0:
                if code[idx] == '{':
                    brace_count += 1
                elif code[idx] == '}':
                    brace_count -= 1
                if brace_count > 0:
                    body_content += code[idx]
                idx += 1
                
            end_line = get_line(idx)
            
            # Find function calls inside body
            calls = set()
            call_pattern = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
            for c_match in call_pattern.finditer(body_content):
                call_name = c_match.group(1)
                if call_name not in ('if', 'for', 'while', 'switch', 'return', 'sizeof', 'catch'):
                    calls.add(call_name)
                    
            definitions.append({
                "name": name,
                "return_type": ret_type,
                "parameters": params,
                "start_line": start_line,
                "end_line": end_line,
                "calls": list(calls)
            })

    # Symbols (Global variables roughly)
    symbols = []
    
    return {
        "includes": includes,
        "dependencies": dependencies,
        "declarations": declarations,
        "functions": definitions,
        "symbols": symbols
    }

if __name__ == "__main__":
    test_code = """
    #include <stdio.h>
    #include "utils.h"
    
    void copy_data(char *input);
    
    int main(int argc, char** argv) {
        char buffer[10];
        copy_data(buffer);
        printf("done\\n");
        return 0;
    }
    """
    
    res = parse_c_code(test_code)
    import json
    print(json.dumps(res, indent=2))
