import re

def get_code_context(code: str, line_num: int, context_lines: int = 5, func_start: int = None, func_end: int = None) -> str:
    """
    Extract surrounding lines of code for better LLM context.
    If function bounds are provided, includes the whole function and summarizes control flow.
    """
    if not code:
        return ""
        
    lines = code.splitlines()
    total_lines = len(lines)
    target_idx = line_num - 1
    
    if target_idx < 0 or target_idx >= total_lines:
        return ""

    if func_start is not None and func_end is not None:
        start_idx = max(0, func_start - 1)
        end_idx = min(total_lines, func_end)
    else:
        start_idx = max(0, target_idx - context_lines)
        end_idx = min(total_lines, target_idx + context_lines + 1)
        
    context = ["--- CODE CONTEXT ---"]
    
    # Lightweight control-flow extraction
    control_flow_summary = []
    if func_start is not None and func_end is not None:
        brace_level = 0
        block_stack = []
        
        # Regexes for control flow
        cf_pattern = re.compile(r'^\s*(if|while|for|switch|else\s+if|else)\b(.*)')
        early_return_pattern = re.compile(r'^\s*(return|goto|break|continue)\b')
        resource_pattern = re.compile(r'\b(malloc|calloc|free|fopen|fclose|acquire|release|lock|unlock)\b')
        
        for i in range(start_idx, end_idx):
            line_text = lines[i]
            
            # Very basic brace counting
            for char in line_text:
                if char == '{':
                    brace_level += 1
                elif char == '}':
                    brace_level -= 1
                    # pop blocks
                    while block_stack and block_stack[-1]['level'] > brace_level:
                        block_stack.pop()

            # Detect blocks
            cf_match = cf_pattern.search(line_text)
            if cf_match:
                block_stack.append({'level': brace_level + (1 if '{' not in line_text else 0), 'text': line_text.strip(), 'line': i + 1})
            
            # Detect early returns / error handling
            if early_return_pattern.search(line_text):
                control_flow_summary.append(f"Early return/break at line {i + 1}: {line_text.strip()}")
                
            # Pointer checks / resources
            if resource_pattern.search(line_text) or ('!=' in line_text and 'NULL' in line_text) or ('==' in line_text and 'NULL' in line_text):
                 control_flow_summary.append(f"Resource/Pointer operation at line {i + 1}: {line_text.strip()}")

            # If we hit the target line, record the active blocks
            if i == target_idx and block_stack:
                control_flow_summary.append("Target line is enclosed in:")
                for b in block_stack:
                    control_flow_summary.append(f"  - Line {b['line']}: {b['text']}")
                    
        if control_flow_summary:
            context.append("--- CONTROL FLOW SUMMARY ---")
            context.extend(control_flow_summary)
            context.append("----------------------------")

    for i in range(start_idx, end_idx):
        current_line = i + 1
        line_content = lines[i]
        
        if i == target_idx:
            context.append(f"{current_line}: >>> DETECTED LINE <<< {line_content}")
        else:
            context.append(f"{current_line}: {line_content}")
            
    context.append("--- END CODE CONTEXT ---")
    
    return "\n".join(context)
