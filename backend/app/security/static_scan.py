import re
from typing import List, Dict

from app.security.vulnerability_map import VULNERABILITY_PATTERNS
from app.security.automotive_rules import AUTOMOTIVE_PATTERNS


class StaticScanner:
    """
    Deterministic static scanner for C/C++ source code.

    Regex rules are used for direct vulnerability patterns.
    Additional context-aware checks are used for pointer
    dereferences and unsafe operations.
    """

    def __init__(self):
        self.patterns = VULNERABILITY_PATTERNS.copy()
        self.patterns.update(AUTOMOTIVE_PATTERNS)

    # =========================================================
    # Utility
    # =========================================================

    @staticmethod
    def _add_finding(
        vulnerabilities: List[Dict],
        vuln_type: str,
        severity: str,
        category: str,
        line_num: int,
        line: str,
        description: str = "",
        source: str = "PROJECT_RULE"
    ):
        vulnerabilities.append(
            {
                "type": vuln_type,
                "severity": severity,
                "category": category,
                "line": line_num,
                "code": line.strip(),
                "description": description,
                "source": source
            }
        )

    @staticmethod
    def _mask_non_code(code: str) -> List[str]:
        """Mask comments and literals while preserving source line positions."""
        masked = []
        state = "code"
        escaped = False
        index = 0

        while index < len(code):
            char = code[index]
            if state == "line_comment":
                if char == "\n":
                    state = "code"
                    masked.append(char)
                else:
                    masked.append(" ")
                index += 1
                continue

            if state == "block_comment":
                if char == "\n":
                    masked.append(char)
                else:
                    masked.append(" ")
                if char == "*" and index + 1 < len(code) and code[index + 1] == "/":
                    masked.append(" ")
                    index += 2
                    state = "code"
                    continue
                index += 1
                continue

            if state in ("string", "char"):
                if char == "\n":
                    state = "code"
                    escaped = False
                    masked.append(char)
                else:
                    masked.append(" ")
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                        state = "code"
                index += 1
                continue

            if char == "/":
                if index + 1 < len(code) and code[index + 1] == "/":
                    state = "line_comment"
                    masked.extend([" ", " "])
                    index += 2
                    continue
                if index + 1 < len(code) and code[index + 1] == "*":
                    state = "block_comment"
                    masked.extend([" ", " "])
                    index += 2
                    continue
                masked.append(char)
            elif char == '"':
                state = "string"
                masked.append(" ")
            elif char == "'":
                state = "char"
                masked.append(" ")
            else:
                masked.append(char)

            index += 1

        return "".join(masked).splitlines()

    # =========================================================
    # NULL POINTER ANALYSIS
    # =========================================================

    def _check_null_pointer(
        self,
        lines: List[str],
        source_lines: List[str],
        vulnerabilities: List[Dict],
    ):
        """
        Detect actual dereferences of pointers that are known
        to be initialized to NULL/NULLPTR.

        Example detected:

            char *ptr = NULL;
            printf("%d", *ptr);

        The declaration itself is NOT reported.
        """

        null_pointers = set()

        for i, line in enumerate(lines):

            stripped = line.strip()

            # -------------------------------------------------
            # Detect:
            # char *ptr = NULL;
            # int *p = NULL;
            # ptr = NULL;
            # -------------------------------------------------

            match = re.search(
                r"\b(?:char|int|long|short|float|double|void)"
                r"\s*\*+\s*(\w+)\s*=\s*(?:NULL|nullptr|0)\s*;",
                stripped,
                re.IGNORECASE,
            )

            if match:
                null_pointers.add(match.group(1))
                continue

            assignment = re.search(
                r"\b(\w+)\s*=\s*(?:NULL|nullptr)\s*;",
                stripped,
                re.IGNORECASE,
            )

            if assignment:
                null_pointers.add(assignment.group(1))
                continue

            # -------------------------------------------------
            # Check actual dereference
            # -------------------------------------------------

            for pointer in list(null_pointers):

                dereference = re.search(
                    rf"\*\s*{re.escape(pointer)}\b",
                    stripped,
                )

                if dereference:

                    self._add_finding(
                        vulnerabilities,
                        vuln_type="NULL_POINTER",
                        severity="HIGH",
                        category="NULL_POINTER",
                        line_num=i + 1,
                        line=source_lines[i],
                        description=(
                            f"Pointer '{pointer}' is known to be NULL "
                            "and is dereferenced."
                        ),
                    )

                    # Avoid repeatedly reporting the same pointer
                    null_pointers.discard(pointer)

    # =========================================================
    # UNSAFE STRING OPERATIONS
    # =========================================================

    def _check_unsafe_strings(
        self,
        lines: List[str],
        source_lines: List[str],
        vulnerabilities: List[Dict],
    ):
        """
        Detect inherently unsafe C string functions.

        Examples:
            gets(buffer);
            strcpy(dest, src);
            strcat(dest, src);
        """

        unsafe_functions = {
            "gets": "CRITICAL",
            "strcpy": "HIGH",
            "strcat": "HIGH",
            "sprintf": "HIGH",
        }

        for i, line in enumerate(lines):

            stripped = line.strip()

            for function, severity in unsafe_functions.items():

                if re.search(
                    rf"\b{function}\s*\(",
                    stripped,
                ):

                    self._add_finding(
                        vulnerabilities,
                        vuln_type="UNSAFE_STRING_OPS",
                        severity=severity,
                        category="UNSAFE_STRING_OPS",
                        line_num=i + 1,
                        line=source_lines[i],
                        description=(
                            f"Use of unsafe string function "
                            f"'{function}()' without explicit "
                            "bounds control."
                        ),
                    )

    # =========================================================
    # BOUNDARY ANALYSIS
    # =========================================================

    def _check_boundary_violations(
        self,
        lines: List[str],
        source_lines: List[str],
        vulnerabilities: List[Dict],
    ):
        """
        Detect obvious fixed-buffer boundary issues.

        Example:

            char buffer[10];
            strcpy(buffer, input);
        """

        buffers = {}

        for i, line in enumerate(lines):

            stripped = line.strip()

            # Detect fixed-size arrays
            match = re.search(
                r"\b(?:char|int|short|long|float|double)"
                r"\s+(\w+)\s*\[\s*(\d+)\s*\]",
                stripped,
            )

            if match:
                variable = match.group(1)
                size = int(match.group(2))
                buffers[variable] = size
                continue

            # Detect strcpy into known fixed buffer
            strcpy_match = re.search(
                r"\bstrcpy\s*\(\s*(\w+)\s*,",
                stripped,
            )

            if strcpy_match:

                destination = strcpy_match.group(1)

                if destination in buffers:

                    self._add_finding(
                        vulnerabilities,
                        vuln_type="BOUNDARY_VIOLATION",
                        severity="HIGH",
                        category="BOUNDARY_VIOLATION",
                        line_num=i + 1,
                        line=source_lines[i],
                        description=(
                            f"'{destination}' is a fixed-size "
                            f"buffer of {buffers[destination]} bytes "
                            "and is passed to strcpy(), which performs "
                            "no destination bounds checking."
                        ),
                    )

    # =========================================================
    # REGEX RULES
    # =========================================================

    def _run_pattern_rules(
        self,
        lines: List[str],
        source_lines: List[str],
        vulnerabilities: List[Dict],
    ):
        """
        Run existing deterministic vulnerability patterns.

        These rules are retained for categories that are directly
        identifiable from a single source line.
        """

        for vuln_type, pattern_info in self.patterns.items():

            pattern = pattern_info["pattern"]
            severity = pattern_info["severity"]

            for line_num, line in enumerate(lines, start=1):

                if re.search(
                    pattern,
                    line,
                    re.IGNORECASE,
                ):

                    # Avoid duplicate NULL_POINTER findings because
                    # NULL_POINTER is now handled contextually.
                    if vuln_type == "NULL_POINTER":
                        continue

                    # Avoid duplicate unsafe string findings because
                    # these are handled explicitly above.
                    if vuln_type == "UNSAFE_STRING_OPS":
                        continue

                    # Avoid duplicate boundary findings.
                    if vuln_type == "BOUNDARY_VIOLATION":
                        continue

                    self._add_finding(
                        vulnerabilities,
                        vuln_type=vuln_type,
                        severity=severity,
                        category=pattern_info.get(
                            "category",
                            vuln_type,
                        ),
                        line_num=line_num,
                        line=source_lines[line_num - 1],
                        description=pattern_info.get(
                            "description",
                            "",
                        ),
                    )

    def _check_division_by_zero(
        self,
        lines: List[str],
        source_lines: List[str],
        vulnerabilities: List[Dict],
    ):
        """Detect division by a variable or literal zero in executable code."""
        division_pattern = re.compile(
            r"(?<![/%])/(?![/])\s*(?P<divisor>[A-Za-z_]\w*|[-+]?\d+)"
        )
        guard_pattern = re.compile(
            r"\bif\s*\([^)]*\b{divisor}\b\s*(?:!=|>)\s*0"
        )

        for index, line in enumerate(lines):
            match = division_pattern.search(line)
            if not match:
                continue

            divisor = match.group("divisor")
            if divisor.lstrip("+-").isdigit() and int(divisor) != 0:
                continue

            guarded = False
            if not divisor.lstrip("+-").isdigit():
                guard = guard_pattern.pattern.format(divisor=re.escape(divisor))
                previous_lines = lines[max(0, index - 5):index]
                guarded = any(re.search(guard, previous, re.IGNORECASE) for previous in previous_lines)
                guarded = guarded or bool(re.search(guard, line[:match.start()], re.IGNORECASE))
            if guarded:
                continue

            self._add_finding(
                vulnerabilities,
                vuln_type="DIVISION_BY_ZERO",
                severity="MEDIUM",
                category="DIVISION_BY_ZERO",
                line_num=index + 1,
                line=source_lines[index],
                description=f"Division uses '{divisor}' without an obvious non-zero guard.",
            )

    # =========================================================
    # DEDUPLICATION
    # =========================================================

    @staticmethod
    def _deduplicate(
        vulnerabilities: List[Dict],
    ) -> List[Dict]:

        unique_map = {}

        for vuln in vulnerabilities:
            # Base key for deduplication
            category = vuln.get("category", vuln.get("type", "UNKNOWN"))
            key = (
                category,
                vuln.get("line", 0),
                vuln.get("code", "").strip(),
            )

            if key not in unique_map:
                unique_map[key] = vuln
            else:
                existing = unique_map[key]
                if existing.get("source") != vuln.get("source") and vuln.get("source"):
                    existing["source"] = "COMBINED"
                    if "supporting_evidence" not in existing:
                        existing["supporting_evidence"] = []
                    existing["supporting_evidence"].append({
                        "source": vuln.get("source"),
                        "severity": vuln.get("severity"),
                        "description": vuln.get("description", vuln.get("message", ""))
                    })

        return list(unique_map.values())

    # =========================================================
    # MAIN SCAN
    # =========================================================

    def scan(self, code: str) -> List[Dict]:
        """
        Scan C/C++ source code for deterministic security findings.
        """

        if not code or not code.strip():
            return []

        vulnerabilities = []

        source_lines = code.splitlines()
        lines = self._mask_non_code(code)

        # -----------------------------------------------------
        # 1. Existing deterministic patterns
        # -----------------------------------------------------

        self._run_pattern_rules(
            lines,
            source_lines,
            vulnerabilities,
        )

        # -----------------------------------------------------
        # 2. Division safety
        # -----------------------------------------------------

        self._check_division_by_zero(
            lines,
            source_lines,
            vulnerabilities,
        )

        # -----------------------------------------------------
        # 3. Context-aware NULL pointer analysis
        # -----------------------------------------------------

        self._check_null_pointer(
            lines,
            source_lines,
            vulnerabilities,
        )

        # -----------------------------------------------------
        # 4. Unsafe C string functions
        # -----------------------------------------------------

        self._check_unsafe_strings(
            lines,
            source_lines,
            vulnerabilities,
        )

        # -----------------------------------------------------
        # 5. Buffer boundary checks
        # -----------------------------------------------------

        self._check_boundary_violations(
            lines,
            source_lines,
            vulnerabilities,
        )

        # -----------------------------------------------------
        # 6. Remove duplicates
        # -----------------------------------------------------

        vulnerabilities = self._deduplicate(
            vulnerabilities
        )

        # Sort by source-code line
        vulnerabilities.sort(
            key=lambda x: x["line"]
        )

        return vulnerabilities