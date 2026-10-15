from __future__ import annotations

from tree_sitter import Language, Parser, Node
import os

# Tree-sitter language bundle path; override with the OCEAN_TREE_SITTER_SO
# environment variable when the bundle lives elsewhere.
TREE_SITTER_SO_PATH = os.environ.get(
    "OCEAN_TREE_SITTER_SO", os.environ.get("PCVD_TREE_SITTER_SO",
    "/home/langgraph/tools/tree_sitter/build/my-languages.so"),
)
import json,re
from collections import deque
from typing import Any

KNOWN_BUFFER_INPUT_FUNCS = {
    # --- File / Socket / Standard I/O ---
    # int read(int fd, void *buf, size_t count);
    'read': [1],
    # ssize_t pread(int fd, void *buf, size_t count, off_t offset);
    'pread': [1],
    # size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
    'fread': [0],
    # char *fgets(char *s, int size, FILE *stream);
    'fgets': [0],
    # char *gets(char *s);  // Deprecated and dangerous, but a classic source
    'gets': [0],
    # ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    'recv': [1],
    # ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, ...);
    'recvfrom': [1],

    # --- C/POSIX: String Formatting (Destination buffer) ---
    # int sprintf(char *str, const char *format, ...);
    'sprintf': [0],
    # int vsprintf(char *str, const char *format, va_list ap);
    'vsprintf': [0],
    # int snprintf(char *str, size_t size, const char *format, ...);
    'snprintf': [0],
    # int vsnprintf(char *str, size_t size, const char *format, va_list ap);
    'vsnprintf': [0],

    # --- C/POSIX: Filesystem / System Information ---
    # char *getcwd(char *buf, size_t size);
    'getcwd': [0],
    # int gethostname(char *name, size_t len);
    # 'get_name': [0],
    'gethostname': [0],
    # int getdomainname(char *name, size_t len);
    'getdomainname': [0],
    # ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
    'readlink': [1],
    # char *realpath(const char *path, char *resolved_path);
    'realpath': [1],
    # int ttyname_r(int fd, char *buf, size_t buflen);
    'ttyname_r': [1],
    # size_t confstr(int name, char *buf, size_t len);
    'confstr': [1],
    # int getlogin_r(char *buf, size_t bufsize);
    'getlogin_r': [0],

    # --- C/POSIX: Re-entrant User/Group Lookups (struct + buffer) ---
    # int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, ...);
    'getpwuid_r': [1, 2],
    # int getpwnam_r(const char *name, struct passwd *pwd, char *buf, ...);
    'getpwnam_r': [1, 2],
    # int getgrgid_r(gid_t gid, struct group *grp, char *buf, ...);
    'getgrgid_r': [1, 2],
    # int getgrnam_r(const char *name, struct group *grp, char *buf, ...);
    'getgrnam_r': [1, 2],
    
    # --- C/POSIX: Inter-Process Communication (IPC) ---
    # ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, ...);
    'mq_receive': [1],

    # --- Linux kernel: userspace / I/O buffer input ---
    # long copy_from_user(void *to, const void __user *from, unsigned long n);
    'copy_from_user': [0],
    '__copy_from_user': [0],
    # long strncpy_from_user(char *dst, const char __user *src, long count);
    'strncpy_from_user': [0],
    # void memcpy_fromio(void *dst, const volatile void __iomem *src, size_t count);
    'memcpy_fromio': [0],
}

# --- NEW: Moved from extract_filtered_local_variables for global use ---
# A richer set of integer type keywords, covering most C projects
INTEGER_KEYWORDS = {
    # C standard integer type keywords
    'int', 'long', 'short', 'char', '_Bool', 'signed', 'unsigned',
    
    # Types from <stddef.h>
    'size_t', 'ssize_t', 'ptrdiff_t',

    # Fixed-width integer types from <stdint.h>
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',

    # Minimum-width integer types from <stdint.h>
    'int_least8_t', 'int_least16_t', 'int_least32_t', 'int_least64_t',
    'uint_least8_t', 'uint_least16_t', 'uint_least32_t', 'uint_least64_t',

    # Fastest minimum-width integer types from <stdint.h>
    'int_fast8_t', 'int_fast16_t', 'int_fast32_t', 'int_fast64_t',
    'uint_fast8_t', 'uint_fast16_t', 'uint_fast32_t', 'uint_fast64_t',

    # Pointer-capable integer types from <stdint.h>
    'intptr_t', 'uintptr_t',

    # Maximum-width integer types from <stdint.h>
    'intmax_t', 'uintmax_t',

    # Common POSIX / <sys/types.h> integer type aliases
    'pid_t', 'uid_t', 'gid_t', 'mode_t', 'dev_t', 'off_t', 'ino_t', 'time_t', 'clock_t'
}

CALL_GRAPH_META_KEY = "__call_graph_metadata__"


def _safe_int(value, default=0):
    """Prevent optional AST/event metadata from entering numeric comparisons."""
    if value is None:
        return int(default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)

class UnionFind:
    """
    A union-find (disjoint set) structure for tracking variable aliases (equivalence classes).
    Implements path compression and union-by-size for efficiency.
    """
    def __init__(self, elements):
        self.parent = {el: el for el in elements}
        self.size = {el: 1 for el in elements}

    def find(self, i):
        if self.parent[i] == i:
            return i
        # Path compression
        self.parent[i] = self.find(self.parent[i])
        return self.parent[i]

    def union(self, i, j):
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i != root_j:
            # Union by size
            if self.size[root_i] < self.size[root_j]:
                root_i, root_j = root_j, root_i
            self.parent[root_j] = root_i
            self.size[root_i] += self.size[root_j]

    def get_set(self, i):
        """Return the whole equivalence set containing element i."""
        root = self.find(i)
        return {el for el in self.parent if self.find(el) == root}

def traverse_outfunc(node, res = None):
    if res is None:
        res = list()
    if node.type == 'function_definition':
        res.append(node)
    else:
        if isinstance(node.children, list):
            for n in node.children:
                res.extend(traverse_outfunc(n, None))
    return res

# def get_func_name(node):
#     for n in node.children:
#         if n.type == 'function_declarator':
#             return n.text.decode('utf-8').split('(')[0].strip()
#     for n in node.children:
#         if n.type == 'pointer_declarator':
#             for child in n.children:
#                  if child.type == 'function_declarator':
#                      return child.text.decode('utf-8').split('(')[0].strip()
#     return None

def get_func_name(node: Node) -> str | None:
    """
    A more robust helper that finds the function name from a function definition node.
    It walks the AST down the declarator field chain to reach the identifier.
    """
    if node.type != 'function_definition':
        return None

    # Tree-sitter's C grammar usually nests the name inside a 'declarator' field.
    declarator_node = node.child_by_field_name('declarator')
    if not declarator_node:
        return None

    # The real function name is usually an 'identifier' node. We must find it inside the
    # declarator, since it may be nested (e.g. inside a pointer_declarator).
    
        # Breadth-first search inside the declarator using a queue
    queue = [declarator_node]
    while queue:
        current = queue.pop(0)
        if current.type == 'identifier':
            return current.text.decode('utf-8')
        # Enqueue children to continue the search
        queue.extend(current.children)
        
    return None


def _unwrap_call_target(node: Node | None) -> Node | None:
    """Peel common wrapper nodes until we reach the meaningful call target."""
    current = node
    while current and current.type in {
        "parenthesized_expression",
        "pointer_expression",
        "cast_expression",
        "qualified_identifier",
    }:
        named_children = [child for child in current.children if child.is_named]
        if not named_children:
            break
        current = named_children[0]
    return current


def _extract_call_target_name(call_expression_node: Node) -> str | None:
    """
    Best-effort extraction of the callee name.
    We keep this lightweight: direct identifiers are resolved, while dynamic
    targets are surfaced as unresolved by the metadata helper below.
    """
    func_node = call_expression_node.child_by_field_name('function')
    func_node = _unwrap_call_target(func_node)
    if not func_node:
        return None

    if func_node.type == 'identifier':
        return func_node.text.decode('utf-8', errors='ignore')

    if func_node.type == 'field_expression':
        field_node = func_node.child_by_field_name('field')
        if field_node and field_node.type == 'field_identifier':
            return field_node.text.decode('utf-8', errors='ignore')
        named_children = [child for child in func_node.children if child.is_named]
        if named_children:
            return named_children[-1].text.decode('utf-8', errors='ignore')

    return None


def _classify_call_target_kind(call_expression_node: Node) -> str:
    func_node = _unwrap_call_target(call_expression_node.child_by_field_name('function'))
    if not func_node:
        return 'unknown'
    if func_node.type == 'identifier':
        return 'direct'
    if func_node.type == 'field_expression':
        return 'field_dispatch'
    return 'indirect'


def collect_call_site_details(node: Node, res: list[dict[str, str]] | None = None):
    if res is None:
        res = []
    if node.type == 'call_expression':
        target_name = _extract_call_target_name(node)
        target_kind = _classify_call_target_kind(node)
        res.append({
            "target_name": target_name or "[unresolved_call]",
            "target_kind": target_kind,
            "code": node.text.decode('utf-8', errors='ignore'),
        })

    for child in node.children:
        collect_call_site_details(child, res)
    return res


def traverse_calls_in_node(node, res=None):
    if res is None:
        res = []
    if node.type == 'call_expression':
        call_name = _extract_call_target_name(node)
        if call_name:
            res.append(call_name)

    for child in node.children:
        traverse_calls_in_node(child, res)
    return list(set(res))

def get_all_function_names_from_file(file_path, language='c'):
    try:
        LANGUAGE = Language(TREE_SITTER_SO_PATH, language)
        parser = Parser()
        parser.set_language(LANGUAGE)
        with open(file_path, 'r') as f:
            source_code = f.read()
        tree = parser.parse(source_code.encode('utf-8'))
        function_nodes = traverse_outfunc(tree.root_node)
        all_names = [name for func_node in function_nodes if (name := get_func_name(func_node))]
        return all_names
    except FileNotFoundError:
        print(f"[Error] File not found: {file_path}")
        return []
    except Exception as e:
        print(f"[Error] Failed to parse file {file_path}: {e}")
        return []

def _get_code_from_file_uncached(function_name, file_path, language='c'):
    try:
        LANGUAGE = Language(TREE_SITTER_SO_PATH, language)
        parser = Parser()
        parser.set_language(LANGUAGE)
        with open(file_path, 'r', encoding='utf8') as f:
            source_code = f.read()
        tree = parser.parse(bytes(source_code,"utf8"))
        function_nodes = traverse_outfunc(tree.root_node)
        for func_node in function_nodes:
            if get_func_name(func_node) == function_name:
                return func_node.text.decode('utf-8', errors='ignore')
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[Error] Failed to parse file {file_path}: {e}")
        return None
    
def get_func_from_code(function_name, source_code, language='c'):
    try:
        LANGUAGE = Language(TREE_SITTER_SO_PATH, language)
        parser = Parser()
        parser.set_language(LANGUAGE)
        tree = parser.parse(bytes(source_code,"utf8"))
        function_nodes = traverse_outfunc(tree.root_node)
        for func_node in function_nodes:
            if get_func_name(func_node) == function_name:
                return func_node.text.decode('utf-8', errors='ignore')
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[Error] Failed to parse code: {e}")
        return None    

def get_code_from_repository(project_path, target_func_name, language='c'):
    lang_extensions = {
        'c': ['.c', '.h'],
        'cpp': ['.cpp', '.hpp', '.cxx', '.h']
    }
    found_functions = []
    for root, dirs, files in os.walk(project_path):
        for file_name in files:
            if any(file_name.endswith(ext) for ext in lang_extensions.get(language, [])):
                file_path = os.path.join(root, file_name)
                content = get_code_from_file(target_func_name, file_path, language)
                if content:
                    print(f"[*] Found target function '{target_func_name}' in file: {file_path}")
                    result = {'file_path': file_path, 'code': content}
                    found_functions.append(result)
    return found_functions

def get_all_function_names_in_project(project_path, language='c'):
    # Set holding all function names; duplicates handled automatically
    all_project_funcs_set = set()
    
    # File extensions to scan, chosen by language
    lang_extensions = {
        'c': ['.c', '.h'],
        'cpp': ['.cpp', '.hpp', '.cxx', '.h']
    }
    
    # Walk the project directory recursively
    print(f"--- Scanning project: {project_path} ---")
    for root, dirs, files in os.walk(project_path):
        for file_name in files:
            # Check whether the file extension matches
            if any(file_name.endswith(ext) for ext in lang_extensions.get(language, [])):
                file_path = os.path.join(root, file_name)
                print(f"Processing file: {file_path}")
                
                # Reuse the existing helper to get all function names in one file
                names_in_file = get_all_function_names_from_file(file_path, language)
                
                # Add any found names to the global set
                if names_in_file:
                    all_project_funcs_set.update(names_in_file)
    
    print("--- Scan complete ---")
    # Convert the set to a sorted list for stable, readable output
    return sorted(list(all_project_funcs_set))


# Legacy K&R-era C omits the return type (implicit int). Tree-sitter then parses
# the definition header as a call expression and the file yields zero function
# definitions. Only used as a fallback retry for such files.
_IMPLICIT_INT_FUNCTION_PATTERN = re.compile(
    r"(?m)^([A-Za-z_]\w*)[ \t]*\(([^;{}]*)\)[ \t]*(?:\n[ \t]*)?\{"
)
_IMPLICIT_INT_KEYWORDS = frozenset(
    {"if", "while", "for", "switch", "return", "sizeof", "defined", "do", "else"}
)


def _inject_implicit_int_return_types(source_code: str) -> str:
    """Prepend `int` to top-level implicit-int function definitions."""

    def _replace(match: "re.Match[str]") -> str:
        name = match.group(1)
        if name in _IMPLICIT_INT_KEYWORDS:
            return match.group(0)
        return f"int {name}({match.group(2)}) {{"

    return _IMPLICIT_INT_FUNCTION_PATTERN.sub(_replace, source_code)


def _parse_file_and_build_graph_data_uncached(file_path: str, language: str = 'c'):
    """
    Internal helper bundling the shared logic: file parsing, function extraction, root identification.
    Returns the core data structures every later stage needs.
    """
    # Assumed .so file path below; adjust as needed
    so_path = TREE_SITTER_SO_PATH
    if not os.path.exists(so_path):
        raise FileNotFoundError(f"Tree-sitter library not found at {so_path}. Please build it first.")
        
    C_LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(C_LANGUAGE)

    with open(file_path, 'r', encoding='utf8') as f:
        source_code = f.read()
    tree = parser.parse(bytes(source_code, "utf8"))

    all_func_nodes = traverse_outfunc(tree.root_node)

    defined_funcs_map = {name: n for n in all_func_nodes if (name := get_func_name(n))}
    if not defined_funcs_map:
        # Fallback: implicit-int (K&R-era) function definitions are invisible to
        # the grammar. Retry once with an injected `int` return type.
        normalized_source = _inject_implicit_int_return_types(source_code)
        if normalized_source != source_code:
            tree = parser.parse(bytes(normalized_source, "utf8"))
            all_func_nodes = traverse_outfunc(tree.root_node)
            defined_funcs_map = {
                name: n for n in all_func_nodes if (name := get_func_name(n))
            }
    all_defined_names = set(defined_funcs_map.keys())
    
    all_internal_callees = set()
    call_graph_diagnostics = {
        "direct_internal_calls": 0,
        "direct_external_calls": 0,
        "field_dispatch_calls": 0,
        "indirect_calls": 0,
        "unknown_calls": 0,
        "unresolved_call_examples": [],
    }
    for func_node in defined_funcs_map.values():
        for site in collect_call_site_details(func_node):
            target_name = site["target_name"]
            target_kind = site["target_kind"]
            if target_kind == "direct":
                if target_name in all_defined_names:
                    all_internal_callees.add(target_name)
                    call_graph_diagnostics["direct_internal_calls"] += 1
                else:
                    call_graph_diagnostics["direct_external_calls"] += 1
            else:
                call_graph_diagnostics[f"{target_kind}_calls"] += 1 if f"{target_kind}_calls" in call_graph_diagnostics else 0
                if len(call_graph_diagnostics["unresolved_call_examples"]) < 8:
                    call_graph_diagnostics["unresolved_call_examples"].append(site["code"])
                
    root_funcs = sorted(list(all_defined_names - all_internal_callees))
    # If there is no clear root (e.g. all functions call each other), treat every function as a possible entry
    if not root_funcs and all_defined_names:
        root_funcs = sorted(list(all_defined_names))

    return defined_funcs_map, all_defined_names, root_funcs, call_graph_diagnostics



def generate_rooted_call_graphs(file_path: str, language: str = 'c'):
    """
    Generate per-root, independent adjacency-list call graphs for the given file.
    The recommended format for logically isolated analysis.

    :return: dict mapping each root function name to the subgraph reachable from it.
             e.g.: {'main': {'main': ['a'], 'a': ['b']}, 'api': {'api': ['c']}}
    """
    try:
        defined_funcs_map, all_defined_names, root_funcs, _ = _parse_file_and_build_graph_data(file_path, language)
        
        # Step 1: first build one complete adjacency list containing all edges
        full_adjacency_list = {}
        for func_name, func_node in defined_funcs_map.items():
            internal_callees = sorted(list({
                site["target_name"]
                for site in collect_call_site_details(func_node)
                if site["target_kind"] == "direct" and site["target_name"] in all_defined_names
            }))
            full_adjacency_list[func_name] = internal_callees

        # Step 2: BFS from each root to build its independent subgraph
        rooted_graphs = {}
        for root in root_funcs:
            sub_graph = {}
            queue = deque([root])
            visited = {root}
            
            while queue:
                current_func = queue.popleft()
                
                # Direct callees of the current function, from the complete graph
                direct_callees = full_adjacency_list.get(current_func, [])
                sub_graph[current_func] = direct_callees
                
                for callee in direct_callees:
                    if callee not in visited:
                        visited.add(callee)
                        queue.append(callee)
            
            rooted_graphs[root] = sub_graph
        
        return rooted_graphs

    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return None


def generate_rooted_call_graphs_with_metadata(file_path: str, language: str = 'c') -> dict[str, Any] | None:
    """
    Compatible with the legacy call-graph format while additionally returning lightweight
    diagnostics, so the unresolved / indirect call ratio can be reported honestly in the paper.
    """
    rooted_graphs = generate_rooted_call_graphs(file_path, language)
    if rooted_graphs is None:
        return None
    try:
        _, _, root_funcs, diagnostics = _parse_file_and_build_graph_data(file_path, language)
    except Exception as e:
        print(f"Error processing call-graph metadata for {file_path}: {e}")
        return {"rooted_graphs": rooted_graphs, "root_funcs": sorted(rooted_graphs.keys())}
    return {
        "rooted_graphs": rooted_graphs,
        "root_funcs": root_funcs,
        "diagnostics": diagnostics,
    }




def _generate_markdown_tree_recursive(func_name, defined_funcs_map, all_defined_names, visited_path, indent_level):
    # (original code, unchanged)
    indent = "  " * indent_level
    if func_name in visited_path:
        return f"{indent}- {func_name} (Recursive Call)\n"
    result_str = f"{indent}- {func_name}\n"
    new_visited_path = visited_path | {func_name}
    func_body_node = defined_funcs_map.get(func_name)
    if not func_body_node:
        return result_str
    callees = traverse_calls_in_node(func_body_node)
    internal_callees = sorted([c for c in callees if c in all_defined_names])
    for callee_name in internal_callees:
        result_str += _generate_markdown_tree_recursive(
            callee_name, defined_funcs_map, all_defined_names, new_visited_path, indent_level + 1
        )
    return result_str

def generate_markdown_call_graph(file_path, language='c'):
    """
    Generate a structured call graph (Markdown format) for the given file.
    """
    try:
        # Call the shared helper directly for the required data
        defined_funcs_map, all_defined_names, root_funcs, _ = _parse_file_and_build_graph_data(file_path, language)

        print(f"Functions defined in file: {list(sorted(all_defined_names))}")
        print(f"Call-graph root nodes found: {root_funcs}")

        markdown_graphs_map = {}
        for root_name in root_funcs:
            markdown_tree = _generate_markdown_tree_recursive(
                root_name, defined_funcs_map, all_defined_names, visited_path=set(), indent_level=0
            )
            markdown_graphs_map[root_name] = markdown_tree.strip()
            
        return markdown_graphs_map

    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return None


# def is_declarator_node(node: Node) -> bool:
#     """
#     Helper: decide whether a node is a declarator.
#     Covers all declarator types plus the identifier of a simple declaration (int err;).
#     """
#     # Cover all known declarator types plus bare identifiers acting as declarators
#     return node.type.endswith('declarator') or node.type == 'identifier'


def is_declarator_node(node: Node) -> bool:
    """
    Helper: decide whether an AST node is a declarator.
    Defined per the tree-sitter C grammar; used to identify variable names and their modifiers.
    """
    return node.type in [
        'identifier',
        'pointer_declarator',
        'array_declarator',
        'init_declarator', # e.g., for `var = 1`
        'parenthesized_declarator'
    ]


def _extract_filtered_local_variables_uncached(function_code: str, language: str = 'c') -> list[str]:
    """
    [Modified version]
    Extract local variable names of the requested types (pointer, array, integer) via AST traversal.
    - Returns variable names only, without types.
    - Variables of other types are filtered out.
    """
    source_bytes = bytes(function_code, "utf8")

    # Check the .so file exists so the error message is clearer
    LANGUAGE = Language(TREE_SITTER_SO_PATH, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(source_bytes)
    
    results = []
    
    def find_nodes_by_type(node: Node, target_type: str, found_nodes: list):
        if node.type == target_type:
            found_nodes.append(node)
        for child in node.children:
            find_nodes_by_type(child, target_type, found_nodes)

    function_bodies = []
    find_nodes_by_type(tree.root_node, 'compound_statement', function_bodies)
    if not function_bodies:
        return []

    main_body = function_bodies[0]

    declaration_nodes = []
    find_nodes_by_type(main_body, 'declaration', declaration_nodes)

    # --- MODIFIED: INTEGER_KEYWORDS has been moved to global scope ---
    # (The old dictionary definition is removed from here)

    for decl_node in declaration_nodes:
        
        first_declarator_node = None
        for child in decl_node.children:
            if is_declarator_node(child):
                type_node_check = decl_node.child_by_field_name('type')
                if child != type_node_check:
                    first_declarator_node = child
                    break
        
        if not first_declarator_node:
            continue

        start_byte = decl_node.start_byte
        end_byte = first_declarator_node.start_byte
        full_type_text = source_bytes[start_byte:end_byte].decode('utf8').strip()

        all_declarators = [child for child in decl_node.children if is_declarator_node(child) and child != decl_node.child_by_field_name('type')]
        
        for declarator_node in all_declarators:
            full_declarator_text = declarator_node.text.decode('utf8')
            # Strip any initializer, e.g. "var = 0" -> "var"
            clean_declarator = full_declarator_text.split('=')[0].strip()
            
            if not clean_declarator:
                continue

            # --- New logic: check whether the variable type qualifies ---
            is_pointer = '*' in clean_declarator
            is_array = '[' in clean_declarator
            
            # split() the type string so keywords match exactly
            type_tokens = set(full_type_text.replace("const", "").replace("static", "").strip().split())
            is_integer = False
            # Only treat it as a pure integer type when it is neither pointer nor array
            if not is_pointer and not is_array:
                if type_tokens.intersection(INTEGER_KEYWORDS): # Use global keywords
                    is_integer = True

            # --- If the type qualifies, extract the variable name ---
            if is_pointer or is_array or is_integer:
                # 1. Strip the array part, e.g. "name[IFNAMSIZ]" -> "name"
                var_name = clean_declarator.split('[')[0]
                # 2. Strip the pointer part, e.g. "*s" -> "s"
                var_name = var_name.lstrip(' *')
                # 3. Final whitespace cleanup
                var_name = var_name.strip()

                if var_name:
                    results.append(var_name)

    return sorted(list(set(results)))



def extract_local_variables(function_code: str, language: str = 'c') -> list[str]:
    """
    [Final refactored version]
    Extract local variables together with their full types via AST traversal.
    - Position-based logic handles type qualifiers like const/static correctly.
    - Resolves all known issues.
    """
    # Note: text must be sliced from the original function code string, so it is passed in
    source_bytes = bytes(function_code, "utf8")

    LANGUAGE = Language(TREE_SITTER_SO_PATH, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(source_bytes)
    
    results = []
    
    def find_nodes_by_type(node: Node, target_type: str, found_nodes: list):
        if node.type == target_type:
            found_nodes.append(node)
        for child in node.children:
            find_nodes_by_type(child, target_type, found_nodes)

    function_bodies = []
    find_nodes_by_type(tree.root_node, 'compound_statement', function_bodies)
    if not function_bodies:
        return []

    main_body = function_bodies[0]

    declaration_nodes = []
    find_nodes_by_type(main_body, 'declaration', declaration_nodes)

    for decl_node in declaration_nodes:
        
        # --- Step 1: find the first declarator node; it is the split point between "type" and "variable" ---
        first_declarator_node = None
        for child in decl_node.children:
            # Skip type nodes and other non-declarator nodes
            if is_declarator_node(child):
                 # Make sure this declarator is not part of the type (e.g. typedef MyInt int;)
                 # In a local variable declaration the first declarator is never the type field
                 type_node_check = decl_node.child_by_field_name('type')
                 if child != type_node_check:
                    first_declarator_node = child
                    break
        
        if not first_declarator_node:
            continue

        # --- Step 2: extract the full type string ---
        # Full type = all text from the declaration start up to the first declarator
        start_byte = decl_node.start_byte
        end_byte = first_declarator_node.start_byte
        full_type_text = source_bytes[start_byte:end_byte].decode('utf8').strip()

        # --- Step 3: walk all declarators, joining each with the full type ---
        all_declarators = [child for child in decl_node.children if is_declarator_node(child) and child != decl_node.child_by_field_name('type')]
        
        for declarator_node in all_declarators:
            full_declarator_text = declarator_node.text.decode('utf8')
            clean_declarator = full_declarator_text.split('=')[0].strip()
            
            # Filter out empty or invalid declarators
            if not clean_declarator:
                continue

            final_declaration = f"{full_type_text} {clean_declarator}"
            results.append(final_declaration)

    return sorted(list(set(results)))


def _get_funcnames_from_file_uncached(file_path, language='c'):
    try:
        res=[]
        LANGUAGE = Language(TREE_SITTER_SO_PATH, language)
        parser = Parser()
        parser.set_language(LANGUAGE)
        with open(file_path, 'r', encoding='utf8') as f:
            source_code = f.read()
        tree = parser.parse(bytes(source_code,"utf8"))
        function_nodes = traverse_outfunc(tree.root_node)
        for func_node in function_nodes:
            res.append(get_func_name(func_node))
        return res
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[Error] Failed to parse file {file_path}: {e}")
        return []


def _parse_code_and_get_funcs(source_code: str, language: str = 'c') -> dict:
    """
    Helper: parse a source code string directly and return the function-name -> AST-node map.
    This is the no-file-IO version of _parse_file_and_build_graph_data.
    """
    so_path = TREE_SITTER_SO_PATH
    if not os.path.exists(so_path):
        raise FileNotFoundError(f"Tree-sitter library not found at {so_path}.")
        
    LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(LANGUAGE)

    tree = parser.parse(bytes(source_code, "utf8"))
    
    all_func_nodes = traverse_outfunc(tree.root_node)
    
    defined_funcs_map = {name: n for n in all_func_nodes if (name := get_func_name(n))}
    return defined_funcs_map

def get_full_call_chain_from_code(
    target_function_name: str, 
    full_file_code: str, 
    language: str = 'c', 
    max_callee_depth: int = 4, # <-- default changed to 4
    max_caller_depth: int = 3  # <-- new caller depth-limit parameter
) -> list[str]:
    """
    Find the complete, recursive, bidirectional call chain of a function within a full code text.
    Covers all upstream callers and all downstream callees, with depth limits in both directions.

    Args:
        target_function_name (str): the target function name, e.g. obtained from a patch.
        full_file_code (str): full file code text containing the target function.
        language (str, optional): programming language. Defaults to 'c'.
        max_callee_depth (int, optional): max depth for downward callee tracing. Defaults to 4.
                                          -1 means unbounded depth.
        max_caller_depth (int, optional): max depth for upward caller tracing. Defaults to 3.
                                          -1 means unbounded depth.

    Returns:
        list[str]: flat list of all function names on the call chain (deduplicated, sorted).
    """
    # Updated the log line to show both depths
    # print(f"--- Finding call chain for '{target_function_name}' "
    #       f"(max upstream depth: {max_caller_depth if max_caller_depth >= 0 else 'unbounded'}, "
    #       f"(max downstream depth: {max_callee_depth if max_callee_depth >= 0 else 'unbounded'}) ---")
    
    try:
        # Step 1: parse the code, build the function-node map (unchanged)
        # Assumes _parse_code_and_get_funcs exists and works
        defined_funcs_map = _parse_code_and_get_funcs(full_file_code, language)
        
        if target_function_name not in defined_funcs_map:
            print(f"[Error] Target function '{target_function_name}' not found in the supplied code.")
            return []

        # Step 2: build the callee graph and the caller graph (unchanged)
        callee_graph = {}
        caller_graph = {}
        all_defined_func_names = set(defined_funcs_map.keys())

        for func_name, func_node in defined_funcs_map.items():
            internal_callees = sorted({
                site["target_name"]
                for site in collect_call_site_details(func_node)
                if site["target_kind"] == "direct" and site["target_name"] in all_defined_func_names
            })
            
            if internal_callees:
                callee_graph[func_name] = internal_callees
            
            for callee in internal_callees:
                caller_graph.setdefault(callee, []).append(func_name)
        
        print("[*] Built the bidirectional intra-file call graph.")

        full_chain_set = {target_function_name}

        # Step 3: trace upward (callers), with a depth limit
        # Queue items are now (function name, current depth)
        caller_queue = deque([(target_function_name, 0)]) 
        visited_callers = {target_function_name}
        
        while caller_queue:
            current_func, current_depth = caller_queue.popleft()
            
            # New: check whether the max depth has been reached
            if max_caller_depth >= 0 and current_depth >= max_caller_depth:
                continue

            callers = caller_graph.get(current_func, [])
            for caller in callers:
                if caller not in visited_callers:
                    visited_callers.add(caller)
                    full_chain_set.add(caller)
                    # New: enqueue the next caller with its incremented depth
                    caller_queue.append((caller, current_depth + 1))

        print(f"[*] Upstream caller trace complete: {len(visited_callers)} related function(s).")

        # Step 4: trace downward (callees), using the new default depth (no logic change)
        callee_queue = deque([(target_function_name, 0)]) 
        visited_callees = {target_function_name}
        
        while callee_queue:
            current_func, current_depth = callee_queue.popleft()
            
            if max_callee_depth >= 0 and current_depth >= max_callee_depth:
                continue

            callees = callee_graph.get(current_func, [])
            for callee in callees:
                if callee not in visited_callees:
                    visited_callees.add(callee)
                    full_chain_set.add(callee)
                    callee_queue.append((callee, current_depth + 1))
        print(f"[*] Downstream callee trace complete: {len(visited_callees)} related function(s).")

        print(f"[*] Full call-chain trace complete: {len(full_chain_set)} unique function(s).")

        return sorted(list(full_chain_set))

    except Exception as e:
        print(f"[Error] Error during analysis: {e}")
        return []
    # print(f"--- Finding the corrected full call chain for '{target_function_name}' ---")
    
    # try:
    #     # Step 1: parse the code, getting all function info in one pass
    #     defined_funcs_map = _parse_code_and_get_funcs(full_file_code, language)
        
    #     if target_function_name not in defined_funcs_map:
    #         print(f"[Error] Target function '{target_function_name}' not found in the given code.")
    #         return []

    #     full_chain_set = {target_function_name}

    #     # Step 2: [FIX] analyze the target function's callees directly, unfiltered
    #     print(f"[*] Directly analyzing all callees of '{target_function_name}' (Callees)...")
    #     target_node = defined_funcs_map[target_function_name]
    #     direct_callees = traverse_calls_in_node(target_node)
    #     full_chain_set.update(direct_callees)
    #     print(f"  -> Direct callees found: {direct_callees}")

    #     # Step 3: build the caller graph (only for upward tracing) and recursively find all callers
    #     print(f"[*] Building graph and recursively finding all upstream callers (Callers)...")
    #     caller_graph = {}
    #     for caller_name, caller_node in defined_funcs_map.items():
    #         callees_inside = traverse_calls_in_node(caller_node)
    #         for callee_name in callees_inside:
    #             if callee_name in defined_funcs_map: # upward tracing only cares about in-file functions
    #                 caller_graph.setdefault(callee_name, []).append(caller_name)
        
    #     # BFS upward from the target function
    #     queue = deque([target_function_name])
    #     visited_for_callers = {target_function_name} # traversal control for this walk only

    #     while queue:
    #         current_func = queue.popleft()
    #         callers = caller_graph.get(current_func, [])
    #         for caller in callers:
    #             if caller not in visited_for_callers:
    #                 full_chain_set.add(caller)
    #                 visited_for_callers.add(caller)
    #                 queue.append(caller)
        
    #     print("[*] Full call-chain tracing complete.")
    #     return sorted(list(full_chain_set))

    # except Exception as e:
    #     print(f"[Error] Error during analysis: {e}")
    #     return []

def _get_enclosing_statement(node: Node) -> Node | None:
    statement_types = {
        "expression_statement", "declaration", "if_statement", "while_statement",
        "for_statement", "do_statement", "return_statement", "switch_statement",
        "case_statement", "labeled_statement"
    }
    current = node
    while current:
        if current.type in statement_types:
            return current
        current = current.parent
    return None

def _get_variable_c_type(root_node: Node, variable_name: str) -> str:
    so_path = TREE_SITTER_SO_PATH
    LANGUAGE = Language(so_path, 'c')
    query_string = f"""(identifier) @variable"""
    query = LANGUAGE.query(query_string)
    captures = query.captures(root_node)
    variable_nodes = [node for node, tag in captures if node.text.decode('utf8') == variable_name]
    
    # --- MODIFIED: look up the declaration first, then parameters ---
    
    # 1. Look for a local variable declaration first
    for identifier_node in variable_nodes:
        declaration_node = identifier_node
        # Walk up to the declaration node
        while declaration_node:
            if declaration_node.type == 'declaration':
                break
            if declaration_node.type == 'function_definition': # beyond local-variable scope
                declaration_node = None
                break
            declaration_node = declaration_node.parent
            
        if not declaration_node: continue
        
        base_type_node = declaration_node.child_by_field_name('type')
        if not base_type_node: continue
        base_type = base_type_node.text.decode('utf8')
        
        # Find the declarator containing this identifier_node
        target_declarator_node = None
        
        # --- [KEY FIX] ---
        # Wrong: for child in declaration_node.children: if 'declarator' in child.type:
        # Right: use the is_declarator_node helper
        for child in declaration_node.children:
            if is_declarator_node(child): # <-- MODIFIED
        # --- [END FIX] ---
                
                # Make sure this declarator is not the type itself
                if child == base_type_node:
                    continue
                    
                q = [child]
                found = False
                while q:
                    curr = q.pop(0)
                    if curr == identifier_node:
                        found = True
                        break
                    q.extend(curr.children)
                if found:
                    target_declarator_node = child
                    break
                    
        if not target_declarator_node: continue
        
        declarator_text = target_declarator_node.text.decode('utf8').split('=')[0].strip()
        modifiers = declarator_text.replace(variable_name, "").strip()
        # Combine the type
        full_type = f"{base_type} {modifiers}" if modifiers else base_type
        return re.sub(r'\s+', ' ', full_type).strip() # collapse extra whitespace

    # 2. If no local declaration is found, check whether it is a function parameter
    param_info = get_parameter_info(root_node, -1, variable_name) # look up by name with index -1
    if param_info:
        return param_info["type"]
        
    return "unknown_type"

def get_parameter_info(root_node: Node, param_index: int, param_name: str | None = None) -> dict | None:
    # --- MODIFIED: allow lookup by index or by name ---
    param_list_query_str = "(parameter_list) @params"
    so_path = TREE_SITTER_SO_PATH
    LANGUAGE = Language(so_path, 'c')
    query = LANGUAGE.query(param_list_query_str)
    captures = query.captures(root_node)
    
    param_list_node = None
    for node, tag in captures:
        ancestor, is_in_func_def = node, False
        while ancestor:
            if ancestor.type == 'function_definition':
                is_in_func_def = True
                break
            ancestor = ancestor.parent
        if is_in_func_def:
            param_list_node = node
            break
            
    if not param_list_node: return None
    
    param_nodes = [child for child in param_list_node.children if child.type == 'parameter_declaration']
    
    target_param_node = None
    if param_name:
        # --- Lookup by name ---
        for node in param_nodes:
            current_var_name = ""
            param_name_node = node.child_by_field_name('declarator')
            if param_name_node:
                q = [param_name_node]
                while q:
                    curr = q.pop(0)
                    if curr.type == 'identifier':
                        current_var_name = curr.text.decode('utf8')
                        break
                    q.extend(curr.children)
            if current_var_name == param_name:
                target_param_node = node
                break
    elif param_index >= 0:
        # --- Lookup by index ---
        if param_index >= len(param_nodes): return None
        target_param_node = param_nodes[param_index]
    
    if not target_param_node: return None

    # --- Extract name and type ---
    variable_name = ""
    param_name_node = target_param_node.child_by_field_name('declarator')
    if param_name_node:
        q = [param_name_node]
        while q:
            curr = q.pop(0)
            if curr.type == 'identifier':
                variable_name = curr.text.decode('utf8')
                break
            q.extend(curr.children)
            
    if not variable_name: 
        # Possibly an unnamed parameter like `int`
        if param_name: return None # a name lookup has definitely failed
        variable_name = f"[unnamed_param_{param_index}]"

    full_text = target_param_node.text.decode('utf8')
    
    # Use the declarator's start offset to split type from name
    declarator_start_byte = param_name_node.start_byte if param_name_node else target_param_node.end_byte
    type_end_byte = declarator_start_byte - target_param_node.start_byte
    param_type_text = full_text[:type_end_byte].strip()

    # Without a declarator (e.g.: int), the type is the whole text
    if not param_name_node:
        param_type_text = full_text.strip()
        
    # --- MODIFIED: robust type extraction ---
    # Extract the declarator text (e.g., "*s", "s[]", "**s")
    declarator_text = param_name_node.text.decode('utf8') if param_name_node else ""
    # Remove the variable name
    modifiers = declarator_text.replace(variable_name, "").strip()
    # Combine
    param_type = f"{param_type_text} {modifiers}" if modifiers else param_type_text
    param_type = re.sub(r'\s+', ' ', param_type).strip()
    
    return {"name": variable_name, "type": param_type}

# --- Main analysis functions ---

# --- Guard-extraction helpers (audit-driven fixes, see GUARD_EXTRACTION_AUDIT.md) ---
# Design principle: fill gaps only, no interface changes; all new rules are conservative — when in doubt, record nothing (zero false captures).

# Per-function goto/label scan cache: key = (function start_byte, hash(function text)).
# Every _find_control_dependencies call needs this scan; caching avoids re-walking the whole function per sink.
_FUNC_GOTO_SCAN_CACHE: dict = {}

# Textual pre-check for sibling guard ifs: an if without any exit keyword cannot be a guard
_GUARD_EXIT_HINT = re.compile(rb'return|break|continue|goto')


def _guard_strip_parens(condition_text: str) -> str:
    """Strip the outermost parens of a condition text (existing cosmetic rule)."""
    if condition_text.startswith('(') and condition_text.endswith(')'):
        inner_text = condition_text[1:-1]
        if not inner_text.split() or inner_text.split()[0] not in INTEGER_KEYWORDS:
            return inner_text
    return condition_text


def _guard_neg_text(condition_text: str) -> str:
    """Text form of a negative-polarity condition (same paren-stripping cosmetics)."""
    return f"!({_guard_strip_parens(condition_text)})"


def _guard_goto_target(goto_node: Node, labels: dict) -> Node | None:
    """Resolve a goto's target labeled_statement; None when not found or ambiguous."""
    name = None
    for ch in goto_node.children:
        if ch.type == 'statement_identifier':
            name = ch.text.decode('utf8')
            break
    if not name:
        return None
    return labels.get(name)


def _guard_body_exits(node: Node | None, labels: dict, sink_start: int,
                      loop_depth: int = 0, depth: int = 0) -> bool:
    """
    Whether executing node (a guard if's branch body) definitely cannot fall through to the
    statement right after it. Exit forms: return; break/continue at the top level of the
    guard body; a goto whose target label is provably after the sink. break/continue inside
    a nested loop only exits the inner construct and does not count; while/for may execute
    zero times, a switch may fall through entirely, and a labeled/case statement may be entered by goto — all conservatively treated as possibly falling through (False). comment nodes in the body are always skipped.
    """
    if node is None or depth > 40:
        return False
    t = node.type
    if t == 'return_statement':
        return True
    if t == 'goto_statement':
        # A goto counts as an exit only if it provably moves control past the sink (label after the sink);
        # backward gotos (retry loops), labels between guard and sink, unknown targets -> not counted
        target = _guard_goto_target(node, labels)
        return bool(target is not None and target.start_byte > sink_start)
    if t == 'break_statement':
        return loop_depth == 0
    if t == 'continue_statement':
        return loop_depth == 0
    if t == 'compound_statement':
        for ch in node.named_children:
            if ch.type == 'comment':
                continue
            if _guard_body_exits(ch, labels, sink_start, loop_depth, depth + 1):
                return True
        return False
    if t == 'if_statement':
        cons = node.child_by_field_name('consequence')
        alt = node.child_by_field_name('alternative')
        if alt is None:
            return False  # falls through for sure when the condition is false
        return (_guard_body_exits(cons, labels, sink_start, loop_depth, depth + 1)
                and _guard_body_exits(alt, labels, sink_start, loop_depth, depth + 1))
    if t == 'else_clause':
        for ch in node.named_children:
            if ch.type == 'comment':
                continue
            return _guard_body_exits(ch, labels, sink_start, loop_depth, depth + 1)
        return False
    if t == 'do_statement':
        # A do-while body executes at least once (including the do { ... } while(0) macro idiom)
        return _guard_body_exits(node.child_by_field_name('body'), labels,
                                 sink_start, loop_depth + 1, depth + 1)
    if t == 'labeled_statement':
        # Labels are transparent to fall-through: a path jumping into the label still runs the
        # statements after it, so fall-through is decided by the tail statement (e.g. in
        # `if (err) { ...; stop_handle: ...; goto no_delete; }`, entering stop_handle still heads to no_delete)
        for ch in node.named_children:
            if ch.type in ('comment', 'statement_identifier'):
                continue
            return _guard_body_exits(ch, labels, sink_start, loop_depth, depth + 1)
        return False
    return False


def _guard_cond_exit_chain(if_node: Node, labels: dict, sink_start: int,
                           depth: int = 0) -> list[str] | None:
    """
    For an else-less guard if (c) BODY: when BODY does not certainly exit but a "conditional-exit"
    chain `if (c) { ...; if (d) <exit>; }` exists, the necessary condition for getting past the
    if to the code below is NOT (c AND d AND ...); returns the condition-text list [c, d, ...], or None when unsure.
    """
    if depth > 8:
        return None
    cond = if_node.child_by_field_name('condition')
    cons = if_node.child_by_field_name('consequence')
    if cond is None or cons is None:
        return None
    cond_text = cond.text.decode('utf8')
    if _guard_body_exits(cons, labels, sink_start):
        return [cond_text]
    tail_if = None
    if cons.type == 'if_statement':
        tail_if = cons
    elif cons.type == 'compound_statement':
        nc = [c for c in cons.named_children if c.type != 'comment']
        if nc and all(c.type in ('expression_statement', 'declaration') for c in nc[:-1]) \
                and nc[-1].type == 'if_statement':
            tail_if = nc[-1]
    if tail_if is None:
        return None
    sub = _guard_cond_exit_chain(tail_if, labels, sink_start, depth + 1)
    if sub is None:
        return None
    return [cond_text] + sub


def _guard_sibling_facts(g: Node, labels: dict, goto_list: list,
                         sink_start: int, sink_end: int) -> list[tuple[str, int, int]]:
    """
    Extract guard facts from preceding sibling ifs (including else-if chains and single guards
    with else), returning [(condition text, guard if start_byte, end_byte)]. Conservative: any ambiguity returns [].
    """
    # 0. goto safety (only needs checking when the function contains goto)
    if labels or goto_list:
        # 0a. Every goto inside the guard must jump past the sink; otherwise a path exists where the
        #     guard condition holds yet the sink is still reachable (or undecidable) -> drop the whole guard
        stack = [g]
        while stack:
            n = stack.pop()
            if n.type == 'goto_statement':
                target = _guard_goto_target(n, labels)
                if target is None or target.start_byte <= sink_start:
                    return []
            stack.extend(n.children)
        # 0b. A label between guard and sink targeted by an earlier goto -> the guard can be bypassed
        for gname, gstart in goto_list:
            tnode = labels.get(gname)
            if tnode is not None and gstart < g.start_byte \
                    and g.end_byte <= tnode.start_byte < sink_start:
                return []

    # 1. Unroll the if / else-if / else chain (this grammar wraps the else branch in an else_clause)
    branches = []  # [(condition_node, consequence_node)]
    cur = g
    final_else = None
    while cur is not None and cur.type == 'if_statement':
        cond = cur.child_by_field_name('condition')
        cons = cur.child_by_field_name('consequence')
        if cond is None or cons is None:
            return []
        branches.append((cond, cons))
        alt = cur.child_by_field_name('alternative')
        if alt is None:
            break
        inner = alt
        if alt.type == 'else_clause':
            named = [c for c in alt.named_children if c.type != 'comment']
            inner = named[0] if named else None
        if inner is not None and inner.type == 'if_statement':
            cur = inner  # else-if: keep unrolling
        else:
            final_else = alt  # the real else branch
            break

    # 2. Path enumeration: paths reaching the sink = each non-exiting branch i (NOT c1..NOT c_{i-1}, +c_i)
    #    + else/fall-through (all negated, when else is absent or non-exiting).
    #    A condition with the same sign on every reachable path -> recorded as a fact.
    exits = [_guard_body_exits(cons, labels, sink_start) for _, cons in branches]
    else_exits = _guard_body_exits(final_else, labels, sink_start) \
        if final_else is not None else False
    reach = []  # ('branch', j) | ('fall', -1)
    for j, ex in enumerate(exits):
        if not ex:
            reach.append(('branch', j))
    if not else_exits:
        reach.append(('fall', -1))
    if not reach:
        return []  # dead code after the guard

    facts: list[tuple[str, int, int]] = []
    for i, (cond, _) in enumerate(branches):
        signs = set()
        covered = True
        for kind, j in reach:
            if kind == 'fall' or i < j:
                signs.add('-')
            elif i == j:
                signs.add('+')
            else:
                covered = False  # this path does not include the condition
                break
        if not covered or len(signs) != 1:
            continue
        cond_text = cond.text.decode('utf8')
        if signs.pop() == '-':
            facts.append((_guard_neg_text(cond_text), g.start_byte, g.end_byte))
        else:
            facts.append((cond_text, g.start_byte, g.end_byte))

    # 3. Single branch, no else, body not certainly exiting: the conditional-exit chain of a trailing nested if
    #    `if (c) { ...; if (d) <exit>; }` -> the condition to reach the code below is !( (c) && (d) )
    if len(branches) == 1 and final_else is None and not exits[0]:
        chain = _guard_cond_exit_chain(g, labels, sink_start)
        if chain is not None and len(chain) >= 2:
            facts.append(("!(" + " && ".join(
                f"({_guard_strip_parens(c)})" for c in chain) + ")",
                g.start_byte, g.end_byte))
    return facts


def _find_control_dependencies(sink_node: Node) -> list[str]:
    """
    [AUDIT FIX - 2026-08] Walk up the AST from the key sink node, collecting the control conditions dominating it:
    1. Nested control (parent nodes): if (A) { SINK } -> A; else branch -> !(A);
       while/for -> the loop condition; switch -> switch (cond), adding case-value constraints when passing a case
       (`cond == X` / fall-through group `cond in {A, B}`; default conservatively unrecorded);
    2. Guard clauses (preceding siblings, scanned in both compound and case bodies):
       if (B) return; SINK -> !(B); supports goto exits (only when the label is after the sink),
       else-if chains, single guards with else, and trailing-nested-if conditional exits !((c) && (d)).
    All rules conservative: ambiguous cases (unknown goto targets, labels that can be jumped into past the guard) are never recorded.
    """
    facts: list[tuple[str, int, int]] = []  # (text, source node start, end)

    # We walk upward starting from the statement containing the SINK
    current_node = _get_enclosing_statement(sink_node)
    if not current_node:
        current_node = sink_node # Fallback
    stmt0 = current_node
    sink_start = stmt0.start_byte
    sink_end = stmt0.end_byte

    # --- Per-function goto/label scan (only needed when the function has goto; text pre-check + content cache) ---
    labels: dict = {}
    goto_list: list = []
    func_root = stmt0
    while func_root and func_root.type != 'function_definition':
        func_root = func_root.parent
    if func_root is not None and b'goto' in func_root.text:
        cache_key = (func_root.start_byte, hash(func_root.text))
        cached = _FUNC_GOTO_SCAN_CACHE.get(cache_key)
        if cached is not None:
            labels, goto_list = cached
        else:
            lmap: dict = {}
            glist: list = []
            stack = [func_root]
            while stack:
                n = stack.pop()
                if n.type == 'goto_statement':
                    for ch in n.children:
                        if ch.type == 'statement_identifier':
                            glist.append((ch.text.decode('utf8'), n.start_byte))
                            break
                elif n.type == 'labeled_statement':
                    for ch in n.children:
                        if ch.type == 'statement_identifier':
                            nm = ch.text.decode('utf8')
                            # Duplicate label name -> ambiguous (None); all goto checks conservatively refuse
                            lmap[nm] = None if nm in lmap else n
                            break
                stack.extend(n.children)
            labels, goto_list = lmap, glist
            if len(_FUNC_GOTO_SCAN_CACHE) < 20000:
                _FUNC_GOTO_SCAN_CACHE[cache_key] = (labels, goto_list)

    while current_node:

        parent = current_node.parent
        if not parent:
            break

        # 1. Check "guard clauses" (preceding siblings)
        # We examine all *preceding siblings* of `current_node` in its parent block;
        # when a case body has no braces its statements hang directly under the case_statement — scan those too
        if parent.type in ('compound_statement', 'case_statement'):
            for child_statement in parent.children:
                # 1a. Stop once we reach the current node
                if child_statement == current_node:
                    break
                # 1b. Guard facts from sibling ifs (including else-if chains)
                if child_statement.type == 'if_statement':
                    # Text pre-check: an if without exit keywords cannot be a guard
                    if not _GUARD_EXIT_HINT.search(child_statement.text):
                        continue
                    facts.extend(_guard_sibling_facts(
                        child_statement, labels, goto_list, sink_start, sink_end))

        # 2. Check "nested control" (parent nodes)
        # We check whether `current_node` lies in the body of `parent` (the parent node)
        control_node_type = parent.type
        if control_node_type in {"if_statement", "while_statement", "for_statement", "switch_statement"}:

            body_node = parent.child_by_field_name('body')
            if not body_node and control_node_type == 'if_statement':
                body_node = parent.child_by_field_name('consequence')

            in_body = bool(body_node and
                           current_node.start_byte >= body_node.start_byte and
                           current_node.end_byte <= body_node.end_byte)
            # else-branch polarity: current_node inside the alternative -> record !(cond)
            in_alt = False
            if control_node_type == 'if_statement' and not in_body:
                alt_node = parent.child_by_field_name('alternative')
                in_alt = bool(alt_node and
                              current_node.start_byte >= alt_node.start_byte and
                              current_node.end_byte <= alt_node.end_byte)

            if in_body or in_alt:
                # Nesting found! Extract the condition
                condition_node = parent.child_by_field_name('condition')

                if condition_node:
                    condition_text = condition_node.text.decode('utf8')
                    if control_node_type == 'switch_statement':
                        facts.append((f"switch ({condition_text})",
                                      parent.start_byte, parent.end_byte))
                    elif in_alt:
                        facts.append((_guard_neg_text(condition_text),
                                      parent.start_byte, parent.end_byte))
                    else:
                        facts.append((condition_text,
                                      parent.start_byte, parent.end_byte))
                elif control_node_type == 'for_statement':
                    # [FIX] The old code applied absolute byte offsets to a node-relative byte string,
                    # yielding 'for <garbage>' for for(;;); now uses relative offsets
                    l_paren = parent.child(1)
                    r_paren = body_node.prev_sibling
                    if l_paren and r_paren and l_paren.type == '(':
                         rel_l = l_paren.start_byte - parent.start_byte
                         rel_r = r_paren.end_byte - parent.start_byte
                         full_cond_text = parent.text[rel_l:rel_r].decode('utf8')
                         facts.append((f"for {full_cond_text}",
                                       parent.start_byte, parent.end_byte))
                    else:
                        facts.append(("for (...)", parent.start_byte, parent.end_byte))

        # 3. Passing through a case: add case-value constraints (fall-through empty case groups merged;
        #    default and code-carrying fall-through conservatively unrecorded)
        elif control_node_type == 'case_statement':
            sw_body = parent.parent
            switch_node = sw_body.parent if sw_body is not None and \
                sw_body.type == 'compound_statement' else None
            if switch_node is not None and switch_node.type == 'switch_statement':
                scond = switch_node.child_by_field_name('condition')
                value = parent.child_by_field_name('value')
                if scond is not None and value is not None:
                    group = [value.text.decode('utf8')]
                    group_ok = True
                    sib = parent.prev_named_sibling
                    while sib is not None and sib.type == 'case_statement':
                        stmts = [c for c in sib.named_children
                                 if c.type.endswith('_statement') or c.type == 'declaration']
                        if not stmts:
                            v = sib.child_by_field_name('value')
                            if v is None:
                                group_ok = False  # default falls in; conservatively give up
                                break
                            group.insert(0, v.text.decode('utf8'))
                            sib = sib.prev_named_sibling
                            continue
                        if stmts[-1].type in ('break_statement', 'return_statement',
                                              'goto_statement', 'continue_statement'):
                            break
                        group_ok = False  # code-carrying fall-through; conservatively give up
                        break
                    if group_ok:
                        scond_text = scond.text.decode('utf8')
                        if len(group) == 1:
                            facts.append((f"{scond_text} == {group[0]}",
                                          parent.start_byte, parent.end_byte))
                        else:
                            facts.append((f"{scond_text} in {{{', '.join(group)}}}",
                                          parent.start_byte, parent.end_byte))

        # 4. Move upward
        if parent.type == 'function_definition':
            break

        current_node = parent # key: we iterate over parent *statements*

    # 5. Label filtering: when the sink is wrapped by a goto-reachable label, decide per goto whether each
    #    fact is still evaluated on that goto path. Let the label L sit at ls and the goto at gs:
    #    - fact source inside L's statement (src_start >= ls): always passed after jumping into L -> keep;
    #    - fact source is an ancestor construct containing both the goto and the sink (e.g. a while
    #      condition) -> evaluated every iteration -> keep;
    #    - forward jump (gs < ls): the fact lies entirely before the goto (src_end <= gs) -> that path
    #      also passes it first -> keep;
    #    - otherwise (a guard before the label bypassed by a backward/forward jump) -> drop.
    if goto_list:
        enclosing = []  # [(label_start)]
        cur = stmt0
        while cur is not None and cur.type != 'function_definition':
            if cur.type == 'labeled_statement':
                lname = None
                for ch in cur.children:
                    if ch.type == 'statement_identifier':
                        lname = ch.text.decode('utf8')
                        break
                if lname:
                    for gn, gs in goto_list:
                        if gn == lname:
                            enclosing.append((cur.start_byte, gs))
            cur = cur.parent
        if enclosing:
            kept = []
            for text, src_start, src_end in facts:
                ok = True
                for ls, gs in enclosing:
                    if src_start >= ls:
                        continue  # inside the labeled statement; always passed after the jump
                    if src_start <= ls and src_start <= gs and src_end >= sink_end \
                            and src_end > gs:
                        continue  # ancestor containing both goto and sink (e.g. while)
                    if gs < ls and src_end <= gs:
                        continue  # forward jump: the fact is evaluated before the jump point
                    ok = False
                    break
                if ok:
                    kept.append((text, src_start, src_end))
            facts = kept

    return sorted({text for text, _, _ in facts})


def control_deps_at_byte(function_code: str, start_byte: int) -> list[str]:
    """
    Computes control dependencies for vd_ultra_kimi's regex-synthesized sinks
    (Field-Carried Object Transfer): parses the function code, locates the node at
    start_byte, then calls _find_control_dependencies. Any failure returns [] (zero false captures preserved).
    """
    try:
        tree = _function_tree_cached(function_code, 'c')
        node = tree.root_node
        while True:
            nxt = None
            for ch in node.children:
                if ch.start_byte <= start_byte < ch.end_byte:
                    nxt = ch
                    break
            if nxt is None:
                break
            node = nxt
        return _find_control_dependencies(node)
    except Exception:
        return []

# --- Structured GuardFact / StateTransitionFact (SHADOW MODE, 2026-08) -----------
# Strictly parallel to _find_control_dependencies: the control_dependence strings are still
# produced verbatim by the original function (zero risk, no single-sourcing); this group only *adds* structured records:
#   * guard_facts    — raw/normalized/polarity/category/position/object-role per control dependence;
#   * event_sequence — ordered state events on the sink path related to the tracked variable/aliases.
# All public entry points (_find_control_guard_facts / guard_facts_at_byte /
# sink_event_sequence) are exception-safe: any internal failure returns [] and never affects the main flow.

# Known "length parameter" positions (only for the LEN hint in object-role annotation; conservative small set)
_GUARD_LEN_ARG_POSITIONS = {
    'memcpy': 2, 'memmove': 2, 'memset': 2,
    'strncpy': 2, 'strlcpy': 2, 'strncat': 2,
    'copy_to_user': 2, 'copy_from_user': 2,
    'copy_to_iter': 2, 'copy_from_iter': 2,
    'skb_copy_bits': 3,
}

_GUARD_CMP_INVERT = {'==': '!=', '!=': '==', '<': '>=', '>=': '<',
                     '>': '<=', '<=': '>'}
_GUARD_CMP_OPS = frozenset(_GUARD_CMP_INVERT)


def _guard_unwrap_parens(node: Node | None) -> Node | None:
    """Strip the outermost parenthesized_expression; None on unexpected shape."""
    while node is not None and node.type == 'parenthesized_expression':
        named = [c for c in node.children if c.is_named]
        if len(named) != 1:
            return None
        node = named[0]
    return node


def _guard_norm_operand(node: Node | None) -> str | None:
    """Conservative operand textualization: NULL->0, casts stripped; only simple shapes recognized, else None."""
    node = _guard_unwrap_parens(node)
    if node is None:
        return None
    while node is not None and node.type == 'cast_expression':
        value = node.child_by_field_name('value')
        if value is None:
            return None
        node = _guard_unwrap_parens(value)
    if node is None:
        return None
    text = node.text.decode('utf8', errors='ignore').strip()
    if not text:
        return None
    if node.type == 'null' or text in ('NULL', 'nullptr'):
        return '0'
    if node.type in ('identifier', 'number_literal', 'field_expression',
                     'subscript_expression', 'call_expression', 'char_literal',
                     'string_literal', 'sizeof_expression', 'true', 'false'):
        return text
    if node.type == 'unary_expression':
        first = node.child(0)
        named = [c for c in node.children if c.is_named]
        if (first is not None and first.type in ('-', '+') and named
                and named[0].type == 'number_literal'):
            return text
    return None


def _guard_norm_expr(node: Node | None, negated: bool = False) -> dict | None:
    """
    SFA-Miner-style conservative normalization (polarity included):
      binary compare -> {"lhs","op","rhs"} (inverse operator when negated);
      && / ||      -> {"logic","operands"} (De Morgan flip when negated,
                    sub-items that fail to parse are recorded as {"raw":..., "unparsed": true});
      !e           -> recursively flip polarity; bare expression e -> e != 0 (e == 0 when negated).
    Unknown shapes always return None (a wrong normalization is worse than none).
    """
    node = _guard_unwrap_parens(node)
    if node is None:
        return None
    t = node.type
    if t == 'binary_expression':
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')
        if left is None or right is None:
            return None
        op_text = node.text[
            left.end_byte - node.start_byte: right.start_byte - node.start_byte
        ].decode('utf8', errors='ignore').strip()
        if op_text in ('&&', '||'):
            if negated:
                op_text = '||' if op_text == '&&' else '&&'
            operands = []
            for child in (left, right):
                sub = _guard_norm_expr(child, negated)
                operands.append(sub if sub is not None else {
                    'raw': child.text.decode('utf8', errors='ignore'),
                    'unparsed': True,
                    # Polarity must ride along when a sub-item fails to parse, or the renderer loses the negation
                    'negated': bool(negated),
                })
            return {'logic': op_text, 'operands': operands}
        if op_text in _GUARD_CMP_OPS:
            lhs = _guard_norm_operand(left)
            rhs = _guard_norm_operand(right)
            if lhs is None or rhs is None:
                return None
            if negated:
                op_text = _GUARD_CMP_INVERT[op_text]
            return {'lhs': lhs, 'op': op_text, 'rhs': rhs}
        return None
    if t == 'unary_expression':
        first = node.child(0)
        named = [c for c in node.children if c.is_named]
        if first is not None and first.type == '!' and named:
            return _guard_norm_expr(named[0], not negated)
        return None
    operand = _guard_norm_operand(node)
    if operand is None:
        return None
    return {'lhs': operand, 'op': '==' if negated else '!=', 'rhs': '0'}


def _guard_confidence(normalized: dict | None) -> str:
    """high=fully parsed with simple operands; medium=compound/call or subscript operands; low=not normalizable."""
    if normalized is None:
        return 'low'
    tier = 'high'

    def visit(item: dict) -> None:
        nonlocal tier
        if item.get('unparsed') or 'logic' in item:
            tier = 'medium'
        for key in ('lhs', 'rhs'):
            value = item.get(key)
            if isinstance(value, str) and re.search(r'[(\[]', value):
                tier = 'medium'
        for sub in item.get('operands') or []:
            if isinstance(sub, dict):
                visit(sub)

    visit(normalized)
    return tier


_GUARD_MACRO_LIKE = re.compile(r'^[A-Z_][A-Z0-9_]{1,}$')


def _guard_condition_vars(cond_node: Node | None) -> list[str]:
    """Variables appearing in a condition (excluding callee names, field names, the NULL macro, and ALL-CAPS macro constants),
    deduplicated in source order. ALL-CAPS identifiers in C are almost always macro/enum constants and have no
    analytic value as constraint subjects; mixed-named enum constants (e.g. MagickFalse) are not excluded — a deliberate
    conservative compromise; leftover constants act only as weak hints on the prompt side."""
    if cond_node is None:
        return []
    names: list[str] = []
    seen: set[str] = set()
    queue = deque([cond_node])
    while queue:
        n = queue.popleft()
        if n.type == 'identifier':
            parent = n.parent
            is_callee = bool(parent is not None
                             and parent.type == 'call_expression'
                             and parent.child_by_field_name('function') == n)
            is_field = bool(parent is not None
                            and parent.type == 'field_expression'
                            and parent.child_by_field_name('field') == n)
            if not is_callee and not is_field:
                name = n.text.decode('utf8', errors='ignore')
                if name not in ('NULL', 'nullptr') \
                        and not _GUARD_MACRO_LIKE.match(name) \
                        and name not in seen:
                    seen.add(name)
                    names.append(name)
        queue.extend(n.children)
    return names


def _guard_unwrap_to_call(node: Node | None) -> Node | None:
    """Unwrap casts/parens down to a call_expression; None when not a call."""
    current = node
    while current is not None:
        if current.type == 'call_expression':
            return current
        if current.type == 'cast_expression':
            current = current.child_by_field_name('value')
            continue
        if current.type == 'parenthesized_expression':
            named = [c for c in current.children if c.is_named]
            current = named[0] if len(named) == 1 else None
            continue
        break
    return None


# Per-function RET-definition scan cache: key = (function start_byte, hash(function text)).
# Every guard fact needs the "nearest var=call(...) definition before cond"; caching avoids
# re-walking the whole function per fact (large functions x many facts is the main cost).
_FUNC_RET_DEFS_CACHE: dict = {}


def _guard_func_ret_defs(func_root: Node) -> tuple:
    """Two kinds of in-function events related to variable provenance (ascending source order):

    ret_defs:     `var = call(...)` definitions (start_byte, var, callee),
                  including declaration initializers and in-condition assignments;
    write_events: any write to var (start_byte, var) — plain assignments / declaration initializers
                  (the ret-def itself included), plus var appearing as a bare identifier argument in a call
                  (possibly written through a macro or out-parameter, e.g. n2s(p, i); read-only passing gets flagged too, but
                  losing a best-effort role hint beats binding a stale value).
    """
    cache_key = (func_root.start_byte, hash(func_root.text))
    cached = _FUNC_RET_DEFS_CACHE.get(cache_key)
    if cached is not None:
        return cached
    defs: list = []
    writes: list = []
    stack = [func_root]
    while stack:
        n = stack.pop()
        if n.type == 'assignment_expression':
            left = n.child_by_field_name('left')
            if left is not None and left.type == 'identifier':
                var = left.text.decode('utf8', errors='ignore')
                writes.append((n.start_byte, var))
                call = _guard_unwrap_to_call(n.child_by_field_name('right'))
                if call is not None:
                    fn = call.child_by_field_name('function')
                    callee = fn.text.decode('utf8', errors='ignore') if fn else ''
                    if callee:
                        defs.append((n.start_byte, var, callee))
        elif n.type == 'init_declarator':
            target = n.child_by_field_name('declarator')
            while target is not None and target.type != 'identifier':
                nxt = target.child_by_field_name('declarator')
                if nxt is None or nxt == target:
                    target = None
                    break
                target = nxt
            if target is not None:
                var = target.text.decode('utf8', errors='ignore')
                if n.child_by_field_name('value') is not None:
                    writes.append((n.start_byte, var))
                call = _guard_unwrap_to_call(n.child_by_field_name('value'))
                if call is not None:
                    fn = call.child_by_field_name('function')
                    callee = fn.text.decode('utf8', errors='ignore') if fn else ''
                    if callee:
                        defs.append((n.start_byte, var, callee))
        elif n.type == 'call_expression':
            args = n.child_by_field_name('arguments')
            for arg in (args.children if args else []):
                if arg.is_named and arg.type == 'identifier':
                    writes.append((n.start_byte,
                                   arg.text.decode('utf8', errors='ignore')))
        stack.extend(n.children)
    defs.sort()
    writes.sort()
    result = (tuple(defs), tuple(writes))
    if len(_FUNC_RET_DEFS_CACHE) < 20000:
        _FUNC_RET_DEFS_CACHE[cache_key] = result
    return result


def _guard_collect_ret_defs(func_root: Node, var_names: set,
                            before_byte: int) -> dict:
    """RET bindings {var: callee} for variables in var_names that have a "unique source":

    Bind only when var has **exactly one write** before before_byte and that write is
    `var = call(...)`. More than one write (reassignment, a definition in another branch,
    a macro/out-param call) means ambiguous provenance or a stale value — prefer no binding.
    """
    defs, writes = _guard_func_ret_defs(func_root)
    out: dict = {}
    for name in var_names:
        sites = [(pos, callee) for pos, var, callee in defs
                 if var == name and pos < before_byte]
        prior_writes = [pos for pos, var in writes
                        if var == name and pos < before_byte]
        if len(sites) == 1 and len(prior_writes) == 1:
            out[name] = sites[0][1]
    return out


def _guard_bind_roles(var_names: list, func_root: Node | None,
                      sink_stmt: Node, cond_byte: int) -> dict:
    """
    Best-effort object-role binding (in-function only, never cross-function):
    1) The predicate variable is the i-th argument of the sink call -> "ARG_i(callee)"; on a known
       length-parameter position, "|LEN" is appended (e.g. n in copy_to_user(dst,src,n) -> ARG_2|LEN);
    2) The variable is the return value of an earlier `var = call(...)` -> "RET(callee)" (nearest definition
       before cond).
    No role is assigned when nothing matches (roles omits that variable).
    """
    roles: dict = {}
    if not var_names:
        return roles
    wanted = set(var_names)
    stack = [sink_stmt]
    while stack:
        n = stack.pop()
        if n.type == 'call_expression':
            fn = n.child_by_field_name('function')
            callee = fn.text.decode('utf8', errors='ignore') if fn else ''
            args = n.child_by_field_name('arguments')
            arg_nodes = [c for c in args.children if c.is_named] if args else []
            for index, arg in enumerate(arg_nodes):
                if arg.type == 'identifier':
                    name = arg.text.decode('utf8', errors='ignore')
                    if name in wanted and name not in roles:
                        role = f'ARG_{index}({callee})'
                        if _GUARD_LEN_ARG_POSITIONS.get(callee) == index:
                            role += '|LEN'
                        roles[name] = role
        stack.extend(n.children)
    remaining = wanted - set(roles)
    if remaining and func_root is not None:
        for name, callee in _guard_collect_ret_defs(
                func_root, remaining, cond_byte).items():
            roles[name] = f'RET({callee})'
    return roles


def _guard_cond_exit_chain_ex(if_node: Node, labels: dict, sink_start: int,
                              depth: int = 0) -> list | None:
    """Node version of _guard_cond_exit_chain: returns condition nodes; None when unsure."""
    if depth > 8:
        return None
    cond = if_node.child_by_field_name('condition')
    cons = if_node.child_by_field_name('consequence')
    if cond is None or cons is None:
        return None
    if _guard_body_exits(cons, labels, sink_start):
        return [cond]
    tail_if = None
    if cons.type == 'if_statement':
        tail_if = cons
    elif cons.type == 'compound_statement':
        nc = [c for c in cons.named_children if c.type != 'comment']
        if nc and all(c.type in ('expression_statement', 'declaration') for c in nc[:-1]) \
                and nc[-1].type == 'if_statement':
            tail_if = nc[-1]
    if tail_if is None:
        return None
    sub = _guard_cond_exit_chain_ex(tail_if, labels, sink_start, depth + 1)
    if sub is None:
        return None
    return [cond] + sub


def _guard_sibling_guard_facts(g: Node, labels: dict, goto_list: list,
                               sink_start: int, sink_end: int) -> list:
    """
    Structured mirror of _guard_sibling_facts: identical conservative rules and path enumeration,
    recording kind/polarity/cond node/positions metadata along the way. Any ambiguity returns [].
    """
    entries: list = []

    # 0. goto safety (identical to _guard_sibling_facts)
    if labels or goto_list:
        stack = [g]
        while stack:
            n = stack.pop()
            if n.type == 'goto_statement':
                target = _guard_goto_target(n, labels)
                if target is None or target.start_byte <= sink_start:
                    return []
            stack.extend(n.children)
        for gname, gstart in goto_list:
            tnode = labels.get(gname)
            if tnode is not None and gstart < g.start_byte \
                    and g.end_byte <= tnode.start_byte < sink_start:
                return []

    # 1. Unroll the if / else-if / else chain (this grammar wraps the else branch in an else_clause)
    branches = []  # [(condition_node, consequence_node)]
    cur = g
    final_else = None
    while cur is not None and cur.type == 'if_statement':
        cond = cur.child_by_field_name('condition')
        cons = cur.child_by_field_name('consequence')
        if cond is None or cons is None:
            return []
        branches.append((cond, cons))
        alt = cur.child_by_field_name('alternative')
        if alt is None:
            break
        inner = alt
        if alt.type == 'else_clause':
            named = [c for c in alt.named_children if c.type != 'comment']
            inner = named[0] if named else None
        if inner is not None and inner.type == 'if_statement':
            cur = inner  # else-if: keep unrolling
        else:
            final_else = alt  # the real else branch
            break

    variant = ('elseif_chain' if len(branches) > 1
               else 'if_else' if final_else is not None else 'simple')
    kind = 'guard_elseif_chain' if len(branches) > 1 else 'guard_clause'

    # 2. Path enumeration (same sign logic as the original function)
    exits = [_guard_body_exits(cons, labels, sink_start) for _, cons in branches]
    else_exits = _guard_body_exits(final_else, labels, sink_start) \
        if final_else is not None else False
    reach = []
    for j, ex in enumerate(exits):
        if not ex:
            reach.append(('branch', j))
    if not else_exits:
        reach.append(('fall', -1))
    if not reach:
        return []

    for i, (cond, _) in enumerate(branches):
        signs = set()
        covered = True
        for reach_kind, j in reach:
            if reach_kind == 'fall' or i < j:
                signs.add('-')
            elif i == j:
                signs.add('+')
            else:
                covered = False
                break
        if not covered or len(signs) != 1:
            continue
        cond_text = cond.text.decode('utf8')
        negated = signs.pop() == '-'
        entries.append({
            'raw': _guard_neg_text(cond_text) if negated else cond_text,
            'kind': kind,
            'polarity': 'negated' if negated else 'positive',
            'cond_node': cond,
            'cond_nodes': None,
            'cond_byte': cond.start_byte,
            'cond_line': cond.start_point[0] + 1,
            'src_start': g.start_byte,
            'src_end': g.end_byte,
            'guard_variant': variant,
        })

    # 3. Single branch, no else, body not certainly exiting: the conditional-exit chain of a trailing nested if
    if len(branches) == 1 and final_else is None and not exits[0]:
        chain = _guard_cond_exit_chain_ex(g, labels, sink_start)
        if chain is not None and len(chain) >= 2:
            raw = "!(" + " && ".join(
                f"({_guard_strip_parens(c.text.decode('utf8'))})"
                for c in chain) + ")"
            entries.append({
                'raw': raw,
                'kind': 'guard_clause',
                'polarity': 'negated',
                'cond_node': chain[0],
                'cond_nodes': chain,
                'cond_byte': chain[0].start_byte,
                'cond_line': chain[0].start_point[0] + 1,
                'src_start': g.start_byte,
                'src_end': g.end_byte,
                'guard_variant': 'nested_tail_if',
            })
    return entries


def _guard_normalize_entry(entry: dict) -> dict | None:
    """Build the conservative normalization per fact category; case-value constraints structured directly, switch kept as raw text."""
    kind = entry.get('kind')
    if kind == 'case_value':
        labels = [str(x) for x in (entry.get('case_labels') or [])]
        scond_text = _node_text(_guard_unwrap_parens(entry.get('cond_node'))).strip()
        if not scond_text or not labels:
            return None
        if len(labels) == 1:
            return {'lhs': scond_text, 'op': '==', 'rhs': labels[0]}
        return {'lhs': scond_text, 'op': 'in', 'rhs': labels}
    if kind == 'switch':
        return None  # switch_value recorded separately as raw text; no predicate-semantics guessing
    cond_nodes = entry.get('cond_nodes')
    if cond_nodes:
        # Trailing nested-if chain: !((c1) && (c2) && ...) <=> !c1 || !c2 || ... (De Morgan)
        operands = []
        for cn in cond_nodes:
            sub = _guard_norm_expr(cn, True)
            operands.append(sub if sub is not None else {
                'raw': _node_text(cn), 'unparsed': True})
        return {'logic': '||', 'operands': operands}
    cond_node = entry.get('cond_node')
    if cond_node is None:
        return None
    return _guard_norm_expr(cond_node, entry.get('polarity') == 'negated')


def _find_control_guard_facts_inner(sink_node: Node) -> list:
    entries: list = []  # internal entries (with temporary keys like cond_node/src_start)

    current_node = _get_enclosing_statement(sink_node)
    if not current_node:
        current_node = sink_node
    stmt0 = current_node
    sink_start = stmt0.start_byte
    sink_end = stmt0.end_byte

    # --- Per-function goto/label scan (same cache, same rules as the original) ---
    labels: dict = {}
    goto_list: list = []
    func_root = stmt0
    while func_root and func_root.type != 'function_definition':
        func_root = func_root.parent
    if func_root is not None and b'goto' in func_root.text:
        cache_key = (func_root.start_byte, hash(func_root.text))
        cached = _FUNC_GOTO_SCAN_CACHE.get(cache_key)
        if cached is not None:
            labels, goto_list = cached
        else:
            lmap: dict = {}
            glist: list = []
            stack = [func_root]
            while stack:
                n = stack.pop()
                if n.type == 'goto_statement':
                    for ch in n.children:
                        if ch.type == 'statement_identifier':
                            glist.append((ch.text.decode('utf8'), n.start_byte))
                            break
                elif n.type == 'labeled_statement':
                    for ch in n.children:
                        if ch.type == 'statement_identifier':
                            nm = ch.text.decode('utf8')
                            lmap[nm] = None if nm in lmap else n
                            break
                stack.extend(n.children)
            labels, goto_list = lmap, glist
            if len(_FUNC_GOTO_SCAN_CACHE) < 20000:
                _FUNC_GOTO_SCAN_CACHE[cache_key] = (labels, goto_list)

    while current_node:

        parent = current_node.parent
        if not parent:
            break

        # 1. Guard clauses (preceding siblings) — same scan scope as the original
        if parent.type in ('compound_statement', 'case_statement'):
            for child_statement in parent.children:
                if child_statement == current_node:
                    break
                if child_statement.type == 'if_statement':
                    if not _GUARD_EXIT_HINT.search(child_statement.text):
                        continue
                    entries.extend(_guard_sibling_guard_facts(
                        child_statement, labels, goto_list, sink_start, sink_end))

        # 2. Nested control (parent nodes)
        control_node_type = parent.type
        if control_node_type in {"if_statement", "while_statement",
                                 "for_statement", "switch_statement"}:

            body_node = parent.child_by_field_name('body')
            if not body_node and control_node_type == 'if_statement':
                body_node = parent.child_by_field_name('consequence')

            in_body = bool(body_node and
                           current_node.start_byte >= body_node.start_byte and
                           current_node.end_byte <= body_node.end_byte)
            in_alt = False
            if control_node_type == 'if_statement' and not in_body:
                alt_node = parent.child_by_field_name('alternative')
                in_alt = bool(alt_node and
                              current_node.start_byte >= alt_node.start_byte and
                              current_node.end_byte <= alt_node.end_byte)

            if in_body or in_alt:
                condition_node = parent.child_by_field_name('condition')

                if condition_node:
                    condition_text = condition_node.text.decode('utf8')
                    if control_node_type == 'switch_statement':
                        entries.append({
                            'raw': f"switch ({condition_text})",
                            'kind': 'switch', 'polarity': 'positive',
                            'cond_node': condition_node, 'cond_nodes': None,
                            'cond_byte': condition_node.start_byte,
                            'cond_line': condition_node.start_point[0] + 1,
                            'src_start': parent.start_byte,
                            'src_end': parent.end_byte,
                            'switch_value': condition_text,
                            'confidence': 'medium',
                        })
                    elif in_alt:
                        entries.append({
                            'raw': _guard_neg_text(condition_text),
                            'kind': 'else_branch', 'polarity': 'negated',
                            'cond_node': condition_node, 'cond_nodes': None,
                            'cond_byte': condition_node.start_byte,
                            'cond_line': condition_node.start_point[0] + 1,
                            'src_start': parent.start_byte,
                            'src_end': parent.end_byte,
                        })
                    else:
                        nested_kind = ('nested_if'
                                       if control_node_type == 'if_statement'
                                       else 'loop_while'
                                       if control_node_type == 'while_statement'
                                       else 'loop_for')
                        entries.append({
                            'raw': condition_text,
                            'kind': nested_kind, 'polarity': 'positive',
                            'cond_node': condition_node, 'cond_nodes': None,
                            'cond_byte': condition_node.start_byte,
                            'cond_line': condition_node.start_point[0] + 1,
                            'src_start': parent.start_byte,
                            'src_end': parent.end_byte,
                        })
                elif control_node_type == 'for_statement':
                    # Same as the original: relative-offset slicing (unconditional forms like for(;;))
                    l_paren = parent.child(1)
                    r_paren = body_node.prev_sibling
                    if l_paren and r_paren and l_paren.type == '(':
                         rel_l = l_paren.start_byte - parent.start_byte
                         rel_r = r_paren.end_byte - parent.start_byte
                         full_cond_text = parent.text[rel_l:rel_r].decode('utf8')
                         entries.append({
                             'raw': f"for {full_cond_text}",
                             'kind': 'loop_for', 'polarity': 'positive',
                             'cond_node': None, 'cond_nodes': None,
                             'cond_byte': parent.start_byte,
                             'cond_line': parent.start_point[0] + 1,
                             'src_start': parent.start_byte,
                             'src_end': parent.end_byte,
                             'for_header': full_cond_text,
                         })
                    else:
                        entries.append({
                            'raw': "for (...)",
                            'kind': 'loop_for', 'polarity': 'positive',
                            'cond_node': None, 'cond_nodes': None,
                            'cond_byte': parent.start_byte,
                            'cond_line': parent.start_point[0] + 1,
                            'src_start': parent.start_byte,
                            'src_end': parent.end_byte,
                            'for_header': "(...)",
                        })

        # 3. Passing through a case: add case-value constraints (same fall-through rules as the original)
        elif control_node_type == 'case_statement':
            sw_body = parent.parent
            switch_node = sw_body.parent if sw_body is not None and \
                sw_body.type == 'compound_statement' else None
            if switch_node is not None and switch_node.type == 'switch_statement':
                scond = switch_node.child_by_field_name('condition')
                value = parent.child_by_field_name('value')
                if scond is not None and value is not None:
                    group = [value.text.decode('utf8')]
                    group_ok = True
                    sib = parent.prev_named_sibling
                    while sib is not None and sib.type == 'case_statement':
                        stmts = [c for c in sib.named_children
                                 if c.type.endswith('_statement') or c.type == 'declaration']
                        if not stmts:
                            v = sib.child_by_field_name('value')
                            if v is None:
                                group_ok = False
                                break
                            group.insert(0, v.text.decode('utf8'))
                            sib = sib.prev_named_sibling
                            continue
                        if stmts[-1].type in ('break_statement', 'return_statement',
                                              'goto_statement', 'continue_statement'):
                            break
                        group_ok = False
                        break
                    if group_ok:
                        scond_text = scond.text.decode('utf8')
                        if len(group) == 1:
                            raw = f"{scond_text} == {group[0]}"
                        else:
                            raw = f"{scond_text} in {{{', '.join(group)}}}"
                        entries.append({
                            'raw': raw,
                            'kind': 'case_value', 'polarity': 'positive',
                            'cond_node': scond, 'cond_nodes': None,
                            'cond_byte': value.start_byte,
                            'cond_line': value.start_point[0] + 1,
                            'src_start': parent.start_byte,
                            'src_end': parent.end_byte,
                            'case_labels': list(group),
                        })

        # 4. Move upward
        if parent.type == 'function_definition':
            break

        current_node = parent

    # 5. Label filtering (same decision as the original)
    if goto_list:
        enclosing = []
        cur = stmt0
        while cur is not None and cur.type != 'function_definition':
            if cur.type == 'labeled_statement':
                lname = None
                for ch in cur.children:
                    if ch.type == 'statement_identifier':
                        lname = ch.text.decode('utf8')
                        break
                if lname:
                    for gn, gs in goto_list:
                        if gn == lname:
                            enclosing.append((cur.start_byte, gs))
            cur = cur.parent
        if enclosing:
            kept = []
            for entry in entries:
                src_start, src_end = entry['src_start'], entry['src_end']
                ok = True
                for ls, gs in enclosing:
                    if src_start >= ls:
                        continue
                    if src_start <= ls and src_start <= gs and src_end >= sink_end \
                            and src_end > gs:
                        continue
                    if gs < ls and src_end <= gs:
                        continue
                    ok = False
                    break
                if ok:
                    kept.append(entry)
            entries = kept

    # 6. Dedup equivalent to the original's `sorted({text})`: for the same raw text keep the earliest cond position
    best: dict = {}
    for entry in entries:
        prev = best.get(entry['raw'])
        if prev is None or entry['cond_byte'] < prev['cond_byte']:
            best[entry['raw']] = entry
    ordered = sorted(best.values(), key=lambda e: (e['cond_byte'], e['raw']))

    # 7. Finalize: normalization / object roles / confidence, ordered by condition source position
    sink_line = stmt0.start_point[0] + 1
    facts: list = []
    for order, entry in enumerate(ordered):
        normalized = _guard_normalize_entry(entry)
        cond_node = entry.get('cond_node')
        var_names = _guard_condition_vars(cond_node)
        roles = _guard_bind_roles(var_names, func_root, stmt0,
                                  entry['cond_byte']) if var_names else {}
        fact = {
            'raw': entry['raw'],
            'normalized': normalized,
            'polarity': entry['polarity'],
            'kind': entry['kind'],
            'cond_line': entry['cond_line'],
            'cond_byte': entry['cond_byte'],
            'sink_line': sink_line,
            'sink_byte': sink_start,
            'order': order,
            # No full-path dominance analysis: only means the condition lies on the extraction path to the sink
            # (it holds along that path). A DOMINATES conclusion requires explicit dominance analysis first.
            'scope_relation': 'PATH_CONDITION',
            'objects': {'vars': var_names, 'roles': roles},
            'confidence': entry.get('confidence') or _guard_confidence(normalized),
        }
        for extra_key in ('switch_value', 'case_labels', 'for_header',
                          'guard_variant'):
            if extra_key in entry:
                fact[extra_key] = entry[extra_key]
        facts.append(fact)
    return facts


def _find_control_guard_facts(sink_node: Node) -> list:
    """
    [SHADOW MODE - 2026-08] Structured mirror of _find_control_dependencies:
    same traversal and conservative rules, producing a GuardFact per control dependence (raw text
    byte-identical to the original function's strings). Purely additive, no existing field touched; any internal exception returns [].
    """
    try:
        return _find_control_guard_facts_inner(sink_node)
    except Exception:
        return []


def guard_facts_at_byte(function_code: str, start_byte: int) -> list:
    """
    Structured version of control_deps_at_byte (used by vd_ultra_kimi's Field-Carried
    synthetic sinks). Any failure returns [] (zero false captures preserved).
    """
    try:
        if start_byte < 0:
            return []
        tree = _function_tree_cached(function_code, 'c')
        node = tree.root_node
        while True:
            nxt = None
            for ch in node.children:
                if ch.start_byte <= start_byte < ch.end_byte:
                    nxt = ch
                    break
            if nxt is None:
                break
            node = nxt
        return _find_control_guard_facts(node)
    except Exception:
        return []


# --- Lightweight StateTransitionFact (event_sequence) ------------------------------
# Per-function statement/condition scan cache: key = function_code. Value is
# (items, token_index): items are (start_byte, line, is_check, text, tokens)
# tuples (sorted by source position); token_index is {identifier token: [item indices]},
# letting sink_event_sequence filter by tracked variable in O(hits) instead of a full-table regex per sink.
_EVENT_SCAN_CACHE: dict = {}

_EVENT_TOKEN_RE = re.compile(r'[A-Za-z_]\w*')


def _event_scan(function_code: str) -> tuple:
    """
    Lightweight scan of all top-level statements and control conditions in a function (coverage derived
    from the existing lifecycle scan; no new analysis). Results sorted by source position and cached (with token index).
    """
    cached = _EVENT_SCAN_CACHE.get(function_code)
    if cached is not None:
        return cached
    items: list = []
    try:
        tree = _function_tree_cached(function_code, 'c')
        wanted = {'expression_statement', 'declaration', 'return_statement'}
        cond_parents = {'if_statement', 'while_statement', 'for_statement',
                        'do_statement', 'switch_statement'}
        queue = deque([tree.root_node])
        while queue:
            node = queue.popleft()
            if node.type in wanted:
                text = re.sub(r'\s+', ' ', _node_text(node).strip())
                if text:
                    items.append((node.start_byte, node.start_point[0] + 1,
                                  False, text))
                continue
            if node.type in cond_parents:
                condition = node.child_by_field_name('condition')
                if condition is not None:
                    text = re.sub(r'\s+', ' ', _node_text(condition).strip())
                    if text:
                        items.append((condition.start_byte,
                                      condition.start_point[0] + 1, True, text))
            queue.extend(node.children)
        items.sort(key=lambda item: item[0])
    except Exception:
        items = []
    indexed: list = []
    token_index: dict = {}
    for idx, (start_byte, line, is_check, text) in enumerate(items):
        tokens = frozenset(_EVENT_TOKEN_RE.findall(text))
        indexed.append((start_byte, line, is_check, text, tokens))
        for tok in tokens:
            token_index.setdefault(tok, []).append(idx)
    result = (tuple(indexed), token_index)
    if len(_EVENT_SCAN_CACHE) < 20000:
        _EVENT_SCAN_CACHE[function_code] = result
    return result


def _event_classify(text: str, is_check: bool, matched: list) -> str:
    """Event classification: check > free > assign > deref > call > use (conservative priority)."""
    if is_check:
        return 'check'
    if _release_event(text):
        return 'free'
    if _simple_assignment(text):
        return 'assign'
    for name in matched:
        if re.search(rf'(?<![A-Za-z0-9_]){re.escape(name)}\s*(?:->|\[)', text) or \
                re.search(rf'\*\s*{re.escape(name)}(?![A-Za-z0-9_])', text):
            return 'deref'
    if re.search(r'[A-Za-z_]\w*\s*\(', text):
        return 'call'
    return 'use'


def sink_event_sequence(function_code: str, sink_start_byte: int,
                        tracked_vars, canonical_object: str | None = None,
                        primary_var: str | None = None,
                        max_events: int = 40) -> list:
    """
    Lightweight StateTransitionFact: ordered events before the sink (the sink statement included)
    related to the tracked variable/aliases: [{seq, kind, text, line, object, inferred}].
    object is normalized to canonical_object (inferred=True only for alias-only hits); without a
    canonical, if one event hits multiple different variables (no reliable normalization), object=None.
    Covers same-function events only; any failure returns [].
    """
    try:
        tracked = list(dict.fromkeys(
            str(v) for v in (tracked_vars or [])
            if v and not str(v).startswith('[')))
        if not tracked or _safe_int(sink_start_byte, -1) < 0:
            return []
        items, token_index = _event_scan(function_code)
        candidate_idx: set = set()
        for v in tracked:
            candidate_idx.update(token_index.get(v, ()))
        events: list = []
        for idx in sorted(candidate_idx):
            start_byte, line, is_check, text, tokens = items[idx]
            if start_byte > sink_start_byte:
                continue
            matched = [v for v in tracked if v in tokens]
            if not matched:
                continue
            if canonical_object:
                obj = canonical_object
                inferred = bool(primary_var) and primary_var not in matched
            elif len(matched) == 1:
                obj, inferred = matched[0], False
            else:
                obj, inferred = None, False
            events.append({
                'seq': len(events),
                'kind': _event_classify(text, is_check, matched),
                'text': text,
                'line': line,
                'object': obj,
                'inferred': inferred,
            })
        if len(events) > max_events:
            # Keep only the max_events nearest to the sink; seq keeps original numbering (truncation visible)
            events = events[-max_events:]
        return events
    except Exception:
        return []


_LIFECYCLE_EVENT_KIND_MAP = {
    'RELEASE': 'free', 'RELEASE_AGAIN': 'free', 'INVALIDATE': 'free',
    'OWNERSHIP_TRANSFER': 'assign', 'ALIAS_CAPTURE': 'assign',
    'OBJECT_REFERENCE': 'assign', 'OBJECT_CREATION_OR_ACQUISITION': 'assign',
    'OBJECT_FIELD_WRITE': 'assign', 'OBJECT_FIELD_STORE': 'assign',
    'USE': 'use', 'GROWTH': 'call',
}


def _lifecycle_event_sequence(events: list, function_code: str) -> list:
    """Derive the ordered sequence from existing lifecycle-path events (pure mapping, no new analysis)."""
    try:
        encoded = (function_code or '').encode('utf8', errors='ignore')
        out: list = []
        for seq, ev in enumerate(events or []):
            start = _safe_int(ev.get('start_byte'), -1)
            line = encoded[:start].count(b'\n') + 1 if start >= 0 else None
            inferred = bool(ev.get('heuristic')) or \
                ev.get('evidence_status') == 'inferred_alias'
            out.append({
                'seq': seq,
                'kind': _LIFECYCLE_EVENT_KIND_MAP.get(
                    str(ev.get('event_kind') or ''), 'use'),
                'text': str(ev.get('code') or ''),
                'line': line,
                'object': ev.get('object_id') or ev.get('abstract_object'),
                'inferred': inferred,
            })
        return out
    except Exception:
        return []

# --- MODIFIED: the sink classifier now returns (category, key node) ---
# --- MODIFIED: the sink classifier now returns (category, key node) ---
def _classify_sink_base(node: Node, variable_c_type: str) -> tuple[str, Node] | None:
    """
    Implements the expert-defined, vulnerability-oriented, layered sink classification rules.
    
    Args:
        node (Node): the located `identifier` node of the tainted variable.
        variable_c_type (str): the variable's C type string (e.g. "char *", "int").
        
    Returns:
        tuple[str, Node] | None: (sink category, key sink node),
                                 or None (benign use or a new Source).
    """
    
    # [helper] Type guessing
    base_type_tokens = set(variable_c_type.replace("const", "").replace("static", "").strip().split())
    is_pointer_or_array = '*' in variable_c_type or '[' in variable_c_type
    is_integer = False
    if not is_pointer_or_array:
        if base_type_tokens.intersection(INTEGER_KEYWORDS):
            is_integer = True
    
    parent = node.parent
    if not parent:
        return None

    # --- Rule 0 (exclusion rule - not a sink) ---
    if parent.type == 'assignment_expression' and parent.child_by_field_name('left') == node:
        return None 

    # --- Rule 1 (general rule: function call - high priority) ---
    ancestor = node
    while ancestor and ancestor.type != 'function_definition':
        if ancestor.type == 'argument_list':
            call_expression_node = ancestor.parent
            if call_expression_node and call_expression_node.type == 'call_expression':
                
                # --- [NEW EXCLUSION LOGIC FOR ISSUE #1] ---
                # Check whether this call is a known Source function and the variable is its buffer argument
                func_name_node = call_expression_node.child_by_field_name('function')
                if func_name_node:
                    func_name = func_name_node.text.decode('utf8')
                    if func_name in KNOWN_BUFFER_INPUT_FUNCS:
                        arg_list_node = call_expression_node.child_by_field_name('arguments')
                        if arg_list_node:
                            args = [arg for arg in arg_list_node.children if arg.is_named]
                            known_buffer_indices = KNOWN_BUFFER_INPUT_FUNCS[func_name]
                            for idx in known_buffer_indices:
                                if idx < len(args):
                                    # Check whether this argument node is the tainted node we are tracking
                                    if args[idx] == node:
                                        return None # this is a Source, not a Sink
                # --- [END NEW EXCLUSION] ---
                                        
                return "Function Call", call_expression_node 
            break 
        ancestor = ancestor.parent
    
        # --- Rule 2 (specific rules: pointer / array - non-call sinks) ---
    if is_pointer_or_array:
        # Rule 2.A: memory dereference (NPD / UAF)
        
        # Pattern 1: *node
        if parent.type == 'pointer_expression' and parent.child(1) == node:
            return "Dereference", parent 
        
        # Pattern 2: node->field
        if parent.type == 'field_expression' and parent.child_by_field_name('argument') == node:
            return "Dereference", parent
            
        # --- [NEW FIX for *(node++) / *(node+1) etc.] ---
        # Pattern 3: check whether the parent expression is dereferenced
        # e.g., (pointer_expression (update_expression (identifier)))
        grandparent = parent.parent
        if grandparent and grandparent.type == 'pointer_expression' and grandparent.child(1) == parent:
            return "Dereference", grandparent
        # --- [END NEW FIX] ---

        # Rule 2.B: array base access (NPD / UAF / OOB Base)
        if parent.type == 'subscript_expression' and parent.child_by_field_name('argument') == node:
            return "Array Base", parent
            
        # Rule 2.C: array index (OOB Read/Write)
        if parent.type == 'subscript_expression' and parent.child_by_field_name('index') == node:
            return "Array Index", parent

    # --- Rule 3 (specific rules: integer - non-call sinks) ---
    if is_integer:
        # Rule 3.A: integer arithmetic (Integer Overflow)
        if parent.type == 'binary_expression':
            op_node = parent.child(1)
            if op_node and op_node.type in {'+', '-', '*', '/', '%', '<<', '>>'}:
                 return "Integer Arithmetic", parent
        
        if parent.type == 'unary_expression':
             op_node = parent.child(0)
             if op_node and op_node.type in {'-'}:
                 return "Integer Arithmetic", parent
                 
        if parent.type == 'update_expression': 
            return "Integer Arithmetic", parent
            
        if parent.type == 'assignment_expression':
            op_node = parent.child(1)
            if op_node and op_node.type in {'+=', '-=', '*=', '/=', '%=', '<<=', '>>='}:
                return "Integer Arithmetic", parent
                        
        # Rule 3.B: array index (OOB Read/Write)
        if parent.type == 'subscript_expression' and parent.child_by_field_name('index') == node:
            return "Array Index", parent

    # --- Default: benign use ---
    return None


def _extract_identifier_like_alias_target(node: Node | None) -> str | None:
    """
    Lightweight alias extraction for common source-level patterns:
    `x`, `&x`, `(x)`, `((type)x)`, `obj.field`, `obj->field`.
    We intentionally keep this shallow and unsound, but it is enough to
    improve context construction on common code patterns.
    """
    current = node
    while current:
        if current.type == 'identifier':
            return current.text.decode('utf8')
        if current.type == 'field_expression':
            base = current.child_by_field_name('argument')
            return _extract_identifier_like_alias_target(base)
        if 'declarator' in current.type:
            # Initializers such as `struct item *p = owner->field` expose `p`
            # through a pointer/array declarator rather than a bare identifier.
            # Following the declarator keeps the field-load data dependency visible
            # without assigning a vulnerability meaning to it.
            nested = current.child_by_field_name('declarator')
            if nested is None:
                named_children = [child for child in current.children if child.is_named]
                nested = named_children[0] if named_children else None
            current = nested
            continue
        if current.type in {'pointer_expression', 'parenthesized_expression', 'cast_expression'}:
            named_children = [child for child in current.children if child.is_named]
            current = named_children[0] if named_children else None
            continue
        break
    return None


def _merge_alias_if_known(uf: UnionFind, lhs_node: Node | None, rhs_node: Node | None):
    lhs_name = _extract_identifier_like_alias_target(lhs_node)
    rhs_name = _extract_identifier_like_alias_target(rhs_node)
    if lhs_name and rhs_name and lhs_name in uf.parent and rhs_name in uf.parent:
        uf.union(lhs_name, rhs_name)


def _rhs_dependency_base_names(rhs_node: Node | None) -> list[str]:
    """Structurally collected value-dependency base names of a computed RHS.

    Only outermost object bases count: subscript indices are skipped
    (`s->cbps[compno]` yields `s`, not `compno`), field expressions resolve
    to their container base, call subtrees are ignored (call arguments do
    not taint the result object), and binary/unary/conditional operands
    recurse. This keeps tainted-length propagation (`n = param + 4`) while
    preventing loop indices mentioned inside subscripts from snowballing
    alias sets into one giant equivalence class.
    """
    names: list[str] = []
    seen: set[str] = set()
    stack = [rhs_node]
    while stack:
        node = stack.pop()
        if node is None:
            continue
        node_type = node.type
        if node_type == 'identifier':
            try:
                name = node.text.decode('utf8')
            except Exception:
                continue
            if name and name not in seen:
                seen.add(name)
                names.append(name)
            continue
        if node_type == 'subscript_expression':
            # Only the array base carries object identity; the index does not.
            stack.append(node.child_by_field_name('argument'))
            continue
        if node_type == 'field_expression':
            stack.append(node.child_by_field_name('argument'))
            continue
        if node_type == 'call_expression':
            continue
        stack.extend(child for child in node.children if child.is_named)
    return names


def _rhs_is_call_like(rhs_node: Node | None) -> bool:
    """True when the RHS value is produced by a call (through casts/parens).

    Call arguments merely mentioning a tainted name must not union the LHS into
    that name's alias set: `error = copy_to_user(buf, ...)` does not make
    `error` an alias of `buf`. Return-value taint is already covered by the
    "any call result is a source" seeding, so skipping call RHS here only
    protects object identity, not recall.
    """
    node = rhs_node
    while node is not None:
        if node.type == 'call_expression':
            return True
        if node.type == 'cast_expression':
            node = node.child_by_field_name('value')
            continue
        if node.type == 'parenthesized_expression':
            inner = [c for c in node.children if c.is_named]
            node = inner[0] if len(inner) == 1 else None
            continue
        return False
    return False


def _merge_computed_rhs_alias(uf: UnionFind, lhs_node: Node | None, rhs_node: Node | None):
    """Recall fallback for computed RHS (`n = param + 4`, `n = arr[param]`).

    When the LHS is a plain local identifier and the shallow alias extraction
    returns None for a binary/subscript RHS, merge the LHS into the alias
    set of the RHS's structural dependency bases (see
    `_rhs_dependency_base_names`). Field-expression LHS is intentionally
    untouched (preserves `obj->f = tainted` behavior), and call-produced
    RHS values are skipped to keep alias sets object-pure.
    """
    try:
        if lhs_node is None or rhs_node is None:
            return
        if lhs_node.type != 'identifier':
            return
        lhs_name = lhs_node.text.decode('utf8')
        if not lhs_name or lhs_name not in uf.parent:
            return
        if _extract_identifier_like_alias_target(rhs_node) is not None:
            return
        if _rhs_is_call_like(rhs_node):
            return
        for name in _rhs_dependency_base_names(rhs_node):
            if name != lhs_name and name in uf.parent:
                uf.union(lhs_name, name)
    except Exception:
        # A regex/parse hiccup must never break the analysis.
        pass


def _identifier_names_in(node: Node | None) -> set[str]:
    """Return identifier spellings below ``node`` without semantic inference."""
    names: set[str] = set()
    queue = deque([node])
    while queue:
        current = queue.popleft()
        if current is None:
            continue
        if current.type == 'identifier':
            try:
                names.add(current.text.decode('utf8'))
            except Exception:
                pass
            continue
        queue.extend(child for child in current.children if child.is_named)
    return names


def _written_plain_identifiers(node: Node | None) -> set[str]:
    """Collect plain variables initialized or updated by a ``for`` component."""
    written: set[str] = set()
    queue = deque([node])
    while queue:
        current = queue.popleft()
        if current is None:
            continue
        target = None
        if current.type == 'assignment_expression':
            target = current.child_by_field_name('left')
        elif current.type == 'update_expression':
            target = current.child_by_field_name('argument')
            if target is None:
                named = [child for child in current.children if child.is_named]
                target = named[0] if len(named) == 1 else None
        elif current.type == 'init_declarator':
            target = current.child_by_field_name('declarator')
        if target is not None:
            name = _extract_identifier_like_alias_target(target)
            if name and target.type != 'field_expression':
                written.add(name)
        queue.extend(child for child in current.children if child.is_named)
    return written


def _binary_operator(node: Node) -> str:
    for child in node.children:
        if not child.is_named:
            return child.type
    return ''


def _integer_literal_value(node: Node | None) -> int | None:
    if node is None or node.type != 'number_literal':
        return None
    try:
        text = node.text.decode('utf8').replace("'", "")
        text = re.sub(r'[uUlL]+$', '', text)
        return int(text, 0)
    except Exception:
        return None


def _affine_index_form(node: Node | None, induction_variable: str) -> tuple[int, int] | None:
    """Parse a narrow integer affine expression ``a*i+b``.

    Only constants, the induction variable, casts/parentheses, unary signs,
    addition/subtraction, and multiplication by a constant are accepted.
    Calls, field reads, shifts, division, and any second variable are rejected.
    """
    if node is None:
        return None
    if node.type == 'identifier':
        try:
            return (1, 0) if node.text.decode('utf8') == induction_variable else None
        except Exception:
            return None
    literal = _integer_literal_value(node)
    if literal is not None:
        return (0, literal)
    if node.type == 'parenthesized_expression':
        named = [child for child in node.children if child.is_named]
        return _affine_index_form(named[0], induction_variable) if len(named) == 1 else None
    if node.type == 'cast_expression':
        return _affine_index_form(node.child_by_field_name('value'), induction_variable)
    if node.type == 'unary_expression':
        named = [child for child in node.children if child.is_named]
        if len(named) != 1:
            return None
        value = _affine_index_form(named[0], induction_variable)
        if value is None:
            return None
        operator = _binary_operator(node)
        if operator == '+':
            return value
        if operator == '-':
            return (-value[0], -value[1])
        return None
    if node.type != 'binary_expression':
        return None
    left = _affine_index_form(node.child_by_field_name('left'), induction_variable)
    right = _affine_index_form(node.child_by_field_name('right'), induction_variable)
    if left is None or right is None:
        return None
    operator = _binary_operator(node)
    if operator == '+':
        return (left[0] + right[0], left[1] + right[1])
    if operator == '-':
        return (left[0] - right[0], left[1] - right[1])
    if operator == '*':
        if left[0] == 0:
            return (left[1] * right[0], left[1] * right[1])
        if right[0] == 0:
            return (right[1] * left[0], right[1] * left[1])
    return None


def _comparison_bound_aliases(
    condition: Node | None,
    induction_variable: str,
    taint_aliases: set[str],
) -> set[str]:
    """Find tainted names compared directly with the loop induction variable."""
    bound_aliases: set[str] = set()
    queue = deque([condition])
    while queue:
        current = queue.popleft()
        if current is None:
            continue
        if current.type == 'binary_expression' and _binary_operator(current) in {
            '<', '<=', '>', '>=', '!=',
        }:
            left_names = _identifier_names_in(current.child_by_field_name('left'))
            right_names = _identifier_names_in(current.child_by_field_name('right'))
            if induction_variable in left_names:
                bound_aliases.update(right_names & taint_aliases)
            if induction_variable in right_names:
                bound_aliases.update(left_names & taint_aliases)
        queue.extend(child for child in current.children if child.is_named)
    return bound_aliases


_BOUND_CONTROLLED_INDEX_ENABLED = os.environ.get(
    'VUL_BOUND_CONTROL_INDEX', '1'
).strip().lower() not in {'0', 'false', 'off'}


def _bound_controlled_index_sinks(
    root_node: Node,
    function_code: str,
    taint_aliases: set[str],
) -> list[dict]:
    """Observe array indices range-controlled by an existing tainted loop bound.

    This is a directional evidence relation, not a vulnerability rule. It never
    creates a source and only accepts induction variables proven in the same
    ``for`` initializer, condition, and update. The index must be affine in that
    variable, so unrelated control dependencies cannot become data-flow sinks.
    """
    if not _BOUND_CONTROLLED_INDEX_ENABLED:
        return []
    sinks: list[dict] = []
    seen_locations: set[int] = set()
    queue = deque([root_node])
    while queue:
        loop = queue.popleft()
        if loop is None:
            continue
        if loop.type != 'for_statement':
            queue.extend(child for child in loop.children if child.is_named)
            continue

        initializer = loop.child_by_field_name('initializer')
        condition = loop.child_by_field_name('condition')
        update = loop.child_by_field_name('update')
        body = loop.child_by_field_name('body')
        if initializer is None or condition is None or update is None or body is None:
            queue.extend(child for child in loop.children if child.is_named)
            continue

        induction_variables = (
            _written_plain_identifiers(initializer)
            & _written_plain_identifiers(update)
            & _identifier_names_in(condition)
        ) - set(taint_aliases)
        for induction_variable in sorted(induction_variables):
            bound_aliases = _comparison_bound_aliases(
                condition, induction_variable, set(taint_aliases)
            )
            if not bound_aliases:
                continue
            body_queue = deque([body])
            while body_queue:
                node = body_queue.popleft()
                if node.type == 'subscript_expression':
                    index_node = node.child_by_field_name('index')
                    affine = _affine_index_form(index_node, induction_variable)
                    if affine is not None and affine[0] != 0:
                        statement = _get_enclosing_statement(node) or node
                        if statement.start_byte not in seen_locations:
                            seen_locations.add(statement.start_byte)
                            index_text = index_node.text.decode('utf8', errors='ignore')
                            bound_text = ', '.join(sorted(bound_aliases))
                            sinks.append({
                                'code': statement.text.decode('utf8', errors='ignore').strip().replace('\n', ' '),
                                'category': 'Bound-Controlled Index',
                                'control_dependence': _find_control_dependencies(node),
                                'guard_facts': _find_control_guard_facts(node),
                                'event_sequence': [],
                                'start_byte': statement.start_byte,
                                'evidence_status': 'observation',
                                'static_notes': [
                                    f"Loop bound {bound_text} controls induction variable "
                                    f"{induction_variable}; affine index {index_text} directly "
                                    "determines this array access range."
                                ],
                            })
                body_queue.extend(child for child in node.children if child.is_named)
        queue.extend(child for child in loop.children if child.is_named)
    return sinks


_SCALAR_FIELD_FLOW_ENABLED = os.environ.get(
    'VUL_SCALAR_FIELD_FLOW', '1'
).strip().lower() not in {'0', 'false', 'off'}

_SCALAR_FIELD_NAME_RE = re.compile(
    r'(?:^|_)(?:size|len|length|count|cnt|index|idx|num|number|capacity|cap|'
    r'bytes?|nbytes|offset)(?:$|_)', re.IGNORECASE,
)

_SCALAR_FIELD_COPY_LENGTH_ARGS = {
    'memcpy': (2,), 'memmove': (2,), 'memset': (2,),
    'strncpy': (2,), 'strlcpy': (2,), 'strncat': (2,),
    'copy_to_user': (2,), 'copy_from_user': (2,),
    '__copy_to_user': (2,), '__copy_from_user': (2,),
    'memcpy_toio': (2,), 'memcpy_fromio': (2,),
}

_SCALAR_FIELD_ALLOCATION_SIZE_ARGS = {
    'malloc': (0,), 'kmalloc': (0,), 'kzalloc': (0,), 'vmalloc': (0,),
    'vzalloc': (0,), 'alloca': (0,), 'realloc': (1,), 'krealloc': (1,),
    'calloc': (0, 1), 'kcalloc': (0, 1), 'kmalloc_array': (0, 1),
}

_SCALAR_FIELD_BULK_WRITE_FUNCS = {
    'memcpy', 'memmove', 'memset', 'copy_from_user', '__copy_from_user',
}


def _unwrap_value_expression(node: Node | None) -> Node | None:
    current = node
    while current is not None and current.type == 'parenthesized_expression':
        named = [child for child in current.children if child.is_named]
        if len(named) != 1:
            return None
        current = named[0]
    return current


def _canonical_value_path(node: Node | None) -> str | None:
    """Return a whitespace-insensitive complete lvalue/value path."""
    current = _unwrap_value_expression(node)
    if current is None:
        return None
    if current.type not in {
        'identifier', 'field_expression', 'pointer_expression',
        'subscript_expression',
    }:
        return None
    text = re.sub(r'\s+', '', _node_text(current))
    return text or None


def _field_leaf_name(node: Node | None) -> str | None:
    current = _unwrap_value_expression(node)
    if current is None or current.type != 'field_expression':
        return None
    field = current.child_by_field_name('field')
    text = _node_text(field).strip()
    return text or None


def _field_container_paths(node: Node | None) -> set[str]:
    """Exact ancestor storage paths of one complete field path."""
    paths: set[str] = set()
    current = _unwrap_value_expression(node)
    while current is not None and current.type == 'field_expression':
        current = current.child_by_field_name('argument')
        path = _canonical_value_path(current)
        if path:
            paths.add(path)
        unwrapped = _unwrap_value_expression(current)
        if unwrapped is not None and unwrapped != current:
            alternate = _canonical_value_path(unwrapped)
            if alternate:
                paths.add(alternate)
        current = unwrapped
    return paths


def _integer_scalar_rhs(node: Node | None, taint_aliases: set[str]) -> bool:
    """Accept arithmetic integer expressions grounded in a taint alias."""
    current = _unwrap_value_expression(node)
    if current is None:
        return False
    if current.type == 'identifier':
        name = _node_text(current)
        return name in taint_aliases or bool(
            re.fullmatch(r'[A-Z_][A-Z0-9_]*', name)
        )
    if current.type in {
        'number_literal', 'char_literal', 'true', 'false', 'sizeof_expression',
    }:
        return True
    if current.type == 'cast_expression':
        type_node = current.child_by_field_name('type')
        value_node = current.child_by_field_name('value')
        return _is_integer_type_text(_node_text(type_node)) and _integer_scalar_rhs(
            value_node, taint_aliases
        )
    if current.type in {'binary_expression', 'unary_expression'}:
        named = [child for child in current.children if child.is_named]
        return bool(named) and all(
            _integer_scalar_rhs(child, taint_aliases) for child in named
        )
    return False


def _field_paths_in(node: Node | None) -> set[str]:
    paths: set[str] = set()
    queue = deque([node])
    while queue:
        current = queue.popleft()
        if current is None:
            continue
        if current.type == 'field_expression':
            path = _canonical_value_path(current)
            if path:
                paths.add(path)
        queue.extend(child for child in current.children if child.is_named)
    return paths


def _call_name_and_arguments(node: Node) -> tuple[str, list[Node]]:
    function = node.child_by_field_name('function')
    arguments = node.child_by_field_name('arguments')
    name = _node_text(function).strip()
    if not re.fullmatch(r'[A-Za-z_]\w*', name):
        return '', []
    return name, list(arguments.named_children) if arguments is not None else []


def _bulk_destination_path(node: Node | None) -> str | None:
    current = _unwrap_value_expression(node)
    if current is not None and current.type == 'pointer_expression':
        if _node_text(current).lstrip().startswith('&'):
            named = [child for child in current.children if child.is_named]
            current = named[0] if len(named) == 1 else None
    return _canonical_value_path(current)


def _scalar_field_flow_sinks(
    root_node: Node,
    function_code: str,
    taint_aliases: set[str],
    source_type: str,
) -> list[dict]:
    """Observe integer taint carried through one exact scalar field path.

    The relation is directional and versioned: it never inserts a field or its
    containing object into the alias set. Whole-object writes kill active field
    versions, and only four security-relevant endpoint classes are emitted.
    """
    if (
        not _SCALAR_FIELD_FLOW_ENABLED
        or not taint_aliases
        or not _is_integer_type_text(source_type)
    ):
        return []

    integer_aliases = {
        name for name in taint_aliases
        if _is_integer_type_text(_get_variable_c_type(root_node, name))
    }
    if not integer_aliases:
        return []

    events: list[tuple[int, int, Node]] = []
    queue = deque([root_node])
    while queue:
        node = queue.popleft()
        if node.type == 'assignment_expression':
            events.append((node.start_byte, 0, node))
        elif node.type == 'call_expression':
            events.append((node.start_byte, 1, node))
        elif node.type == 'subscript_expression':
            events.append((node.start_byte, 2, node))
        elif node.type in {'for_statement', 'while_statement', 'do_statement'}:
            events.append((node.start_byte, 3, node))
        queue.extend(child for child in node.children if child.is_named)
    events.sort(key=lambda item: (item[0], item[1], item[2].end_byte))

    active: dict[str, dict[str, Any]] = {}
    sinks: list[dict] = []
    seen: set[tuple[int, int, str, str]] = set()

    def statement_code(node: Node) -> str:
        statement = _get_enclosing_statement(node) or node
        return statement.text.decode('utf8', errors='ignore').strip().replace('\n', ' ')

    def kill_storage(path: str | None) -> None:
        if not path:
            return
        equivalent_paths = {path}
        if path.startswith('*'):
            equivalent_paths.add(path[1:])
        for field_path, store in list(active.items()):
            if field_path in equivalent_paths or equivalent_paths.intersection(
                store['containers']
            ):
                del active[field_path]

    def emit_use(field_path: str, node: Node, endpoint_kind: str, detail: str) -> None:
        store = active.get(field_path)
        if store is None or node.start_byte <= store['start_byte']:
            return
        statement = _get_enclosing_statement(node) or node
        signature = (store['start_byte'], statement.start_byte, endpoint_kind, field_path)
        if signature in seen:
            return
        seen.add(signature)
        use_code = statement_code(node)
        source_names = ', '.join(store['source_aliases'])
        relation = (
            f"{store['code']} => {use_code} "
            f"[integer scalar {source_names} stored in exact field {field_path}; "
            f"field used as {detail}]"
        )
        sinks.append({
            'code': relation,
            'category': 'Scalar Field Flow',
            'control_dependence': _find_control_dependencies(node),
            'guard_facts': _find_control_guard_facts(node),
            'event_sequence': [],
            'start_byte': statement.start_byte,
            'evidence_status': 'observation',
            'object_identity': f'scalar-field::{field_path}',
            'static_notes': [
                f"Observed integer value flow through complete field path {field_path}; "
                "this relation does not by itself establish a bounds violation."
            ],
        })

    for _, _, node in events:
        if node.type == 'assignment_expression':
            lhs = _unwrap_value_expression(node.child_by_field_name('left'))
            rhs = node.child_by_field_name('right')
            lhs_path = _canonical_value_path(lhs)
            kill_storage(lhs_path)
            leaf = _field_leaf_name(lhs)
            rhs_aliases = sorted(_identifier_names_in(rhs) & integer_aliases)
            if (
                lhs is not None
                and lhs.type == 'field_expression'
                and lhs_path
                and '[' not in lhs_path
                and leaf
                and _SCALAR_FIELD_NAME_RE.search(leaf)
                and rhs_aliases
                and _integer_scalar_rhs(rhs, integer_aliases)
            ):
                active[lhs_path] = {
                    'start_byte': node.start_byte,
                    'code': statement_code(node),
                    'containers': _field_container_paths(lhs),
                    'source_aliases': rhs_aliases,
                }
            continue

        if node.type == 'call_expression':
            function_name, arguments = _call_name_and_arguments(node)
            for position in _SCALAR_FIELD_COPY_LENGTH_ARGS.get(function_name, ()):
                if position < len(arguments):
                    for field_path in _field_paths_in(arguments[position]):
                        emit_use(
                            field_path, node, 'copy_length',
                            f'{function_name} copy length',
                        )
            for position in _SCALAR_FIELD_ALLOCATION_SIZE_ARGS.get(function_name, ()):
                if position < len(arguments):
                    for field_path in _field_paths_in(arguments[position]):
                        emit_use(
                            field_path, node, 'allocation_size',
                            f'{function_name} allocation size',
                        )
            if function_name in _SCALAR_FIELD_BULK_WRITE_FUNCS and arguments:
                kill_storage(_bulk_destination_path(arguments[0]))
            continue

        if node.type == 'subscript_expression':
            index = node.child_by_field_name('index')
            for field_path in _field_paths_in(index):
                emit_use(field_path, node, 'array_index', 'array index')
            continue

        condition = node.child_by_field_name('condition')
        for field_path in _field_paths_in(condition):
            emit_use(field_path, node, 'loop_bound', 'loop bound')

    return sinks


def _propagate_parameter_dependencies(
    uf: UnionFind,
    root_node: Node,
    parameter_name: str,
) -> None:
    """Propagate a formal parameter through directional local assignments.

    This intentionally handles loads such as `local = param->field` without
    treating the reverse store `param->field = local` as an alias between the
    container and the stored object.
    """
    changed = True
    while changed:
        changed = False
        source_aliases = uf.get_set(parameter_name)
        queue = deque([root_node])
        while queue:
            node = queue.popleft()
            lhs_node = rhs_node = None
            if node.type == 'assignment_expression':
                lhs_node = node.child_by_field_name('left')
                rhs_node = node.child_by_field_name('right')
            elif node.type == 'init_declarator':
                lhs_node = node.child_by_field_name('declarator')
                rhs_node = node.child_by_field_name('value')
            if lhs_node is not None and rhs_node is not None:
                # A field store changes container state; it does not make the
                # container itself an alias of the stored object.
                if lhs_node.type != 'field_expression':
                    lhs_name = _extract_identifier_like_alias_target(lhs_node)
                    rhs_name = _extract_identifier_like_alias_target(rhs_node)
                    if (
                        lhs_name and rhs_name
                        and lhs_name in uf.parent and rhs_name in source_aliases
                        and uf.find(lhs_name) != uf.find(parameter_name)
                    ):
                        uf.union(parameter_name, lhs_name)
                        changed = True
                    elif (
                        lhs_name and rhs_name is None
                        and lhs_node.type == 'identifier'
                        and lhs_name in uf.parent
                        and uf.find(lhs_name) != uf.find(parameter_name)
                    ):
                        # Computed RHS: structural base match keeps
                        # `n = param + 4` chains without pulling subscript
                        # indices into the alias set. Call-produced RHS is
                        # skipped: call arguments do not make the result an
                        # alias of the argument objects.
                        try:
                            if (
                                not _rhs_is_call_like(rhs_node)
                                and any(
                                    name in source_aliases
                                    for name in _rhs_dependency_base_names(rhs_node)
                                )
                            ):
                                uf.union(parameter_name, lhs_name)
                                changed = True
                        except Exception:
                            pass
            queue.extend(node.children)


def _pre_analyze_and_build_context_uncached(function_code: str, language: str = 'c') -> dict:
    """
    [Updated] Phase 1: pre-analyze the function code, building a context with alias analysis and generic taint sources.
    A taint source is any variable assigned or modified through a function call.
    """
    so_path = TREE_SITTER_SO_PATH
    LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(bytes(function_code, "utf8"))
    root_node = tree.root_node

    # 1. Extract all local variable names to initialize the union-find
    local_vars = extract_filtered_local_variables(function_code, language)
    uf = UnionFind(local_vars)
    
    high_quality_sources = {} # var_name -> source_info

    # 2. Walk the AST to discover aliases and high-quality taint sources
    q = deque([root_node])
    while q:
        node = q.popleft()

        # --- Lightweight alias analysis: add shallow pointer-aware patterns ---
        if node.type == 'assignment_expression':
            left_node = node.child_by_field_name('left')
            right_node = node.child_by_field_name('right')
            _merge_alias_if_known(uf, left_node, right_node)
            _merge_computed_rhs_alias(uf, left_node, right_node)

        # Handle initializer patterns like `int *p = buf;` / `char *q = &buf;`
        if node.type == 'init_declarator':
            declarator_node = node.child_by_field_name('declarator')
            value_node = node.child_by_field_name('value')
            _merge_alias_if_known(uf, declarator_node, value_node)
            _merge_computed_rhs_alias(uf, declarator_node, value_node)

        # --- [MODIFIED BLOCK FOR ISSUE #2 and #3] ---
        if node.type == 'call_expression':
            func_name_node = node.child_by_field_name('function')
            func_name = func_name_node.text.decode('utf8') if func_name_node else "[unknown_function]"
            
            enclosing_statement = _get_enclosing_statement(node)
            if not enclosing_statement: continue

            # --- [FIX #2] Smart extraction of the Source code snippet ---
            code_snippet = None
            control_flow_types = {"if_statement", "while_statement", "for_statement", "switch_statement"}

            if enclosing_statement.type in control_flow_types:
                condition_node = enclosing_statement.child_by_field_name('condition')
                # Check whether the call expression (node) is inside a condition
                if condition_node and \
                   node.start_byte >= condition_node.start_byte and \
                   node.end_byte <= condition_node.end_byte:
                    
                    keyword_node = enclosing_statement.child(0)
                    keyword_text = keyword_node.text.decode('utf8') if keyword_node else enclosing_statement.type.split('_')[0]

                    if enclosing_statement.type == 'for_statement':
                        body_node = enclosing_statement.child_by_field_name('body')
                        l_paren = enclosing_statement.child(1) # '('
                        r_paren = body_node.prev_sibling if body_node else enclosing_statement.last_named_child # ')'
                        if l_paren and r_paren and l_paren.type == '(':
                            # node.text is relative to the node; slice with relative offsets.
                            control_content_bytes = enclosing_statement.text[
                                l_paren.start_byte - enclosing_statement.start_byte:
                                r_paren.end_byte - enclosing_statement.start_byte
                            ]
                            control_content_text = control_content_bytes.decode('utf8')
                            code_snippet = f"for {control_content_text}"
                        else:
                            code_snippet = f"for ({condition_node.text.decode('utf8')})" # Fallback
                    else:
                        code_snippet = f"{keyword_text} ({condition_node.text.decode('utf8')})"

            if code_snippet is None:
                code_snippet = enclosing_statement.text.decode('utf8').strip().replace('\n', ' ')
            # --- [END FIX #2] ---


            # Pattern 1: variable assigned a function call's return value (e.g., var = func();)
            parent = node.parent
            if parent and parent.type == 'assignment_expression':
                left_node = parent.child_by_field_name('left')
                if left_node and left_node.type == 'identifier':
                    var_name = left_node.text.decode('utf8')
                    if var_name in uf.parent:
                        high_quality_sources[var_name] = {"code": code_snippet, "source_from_function": func_name}

            # --- New, more precise "out-parameter" logic ---
            arg_list_node = node.child_by_field_name('arguments')
            if arg_list_node:
                args = [arg for arg in arg_list_node.children if arg.is_named]

                # Pattern 2: (high-confidence general rule) find arguments passed as "&var"
                for arg in args:
                    if arg.type == 'pointer_expression' and arg.children[0].type == 'identifier':
                        var_name = arg.children[0].text.decode('utf8')
                        if var_name and var_name in uf.parent:
                            if var_name not in high_quality_sources:
                                high_quality_sources[var_name] = {"code": code_snippet, "source_from_function": f"[address passed to {func_name}]"}
                
                # Pattern 3: (high-confidence specific rule) check for known buffer-input functions
                if func_name in KNOWN_BUFFER_INPUT_FUNCS:
                    for arg_index in KNOWN_BUFFER_INPUT_FUNCS[func_name]:
                        if arg_index < len(args) and args[arg_index].type == 'identifier':
                            var_name = args[arg_index].text.decode('utf8')
                            if var_name in uf.parent:
                                if var_name not in high_quality_sources:
                                    # --- [FIX #3] ---
                                    # Return only the function name, not a verbose string
                                    high_quality_sources[var_name] = {"code": code_snippet, "source_from_function": func_name}


        if node.children:
            q.extend(node.children)
            
    return {"union_find": uf, "sources": high_quality_sources}

def _statement_has_tainted_deref(statement_node: Node | None, taint_alias_set: set) -> bool:
    """True when the statement dereferences a tainted alias.

    Covers `alias->field`, `*alias` and `alias[...]`, i.e. the alias is the
    base of a field/pointer/subscript expression. Address-of (`&alias`) does
    not count as a dereference.
    """
    if statement_node is None:
        return False
    q = deque([statement_node])
    while q:
        node = q.popleft()
        base = None
        if node.type in ('field_expression', 'subscript_expression'):
            base = node.child_by_field_name('argument')
        elif node.type == 'pointer_expression':
            first = node.child(0)
            if first is not None and first.type == '*':
                named = [child for child in node.children if child.is_named]
                base = named[0] if named else None
        if base is not None and base.type == 'identifier' \
                and base.text.decode('utf8') in taint_alias_set:
            return True
        q.extend(node.children)
    return False


# --- MODIFIED: refactored analyze_taint_paths_new ---
def analyze_taint_paths(function_code: str, variable_name: str, language: str = 'c'):
    """
    [Refactored - key fixes]
    Implements the hybrid Source strategy:
    1. Prefer _pre_analyze_and_build_context for high-quality taint sources.
    2. If none found, fall back to treating the variable's "declaration" as the taint source.
    """
    # Step 1: run the pre-analysis
    try:
        context = _pre_analyze_and_build_context(function_code, language)
        uf = context["union_find"]
        high_quality_sources = context["sources"]
    except Exception as e:
        print(f"[Error] During pre-analysis phase: {e}")
        return {"path_segments": []}

    # Step 2: get the alias set
    if variable_name not in uf.parent:
        # Variable not found among locals (maybe a parameter or not extracted)
        # For simplicity, if it is not in the UF we cannot analyze it
        return {"path_segments": []}
        
    taint_alias_set = uf.get_set(variable_name)
    
    # --- [NEW] Step 3: hybrid Source lookup ---
    all_found_sources = []
    source_code_snippets_seen = set() # for dedup

    # Strategy 1: find high-quality Sources (preferred)
    for var in taint_alias_set:
        if var in high_quality_sources:
            source_info = high_quality_sources[var]
            if source_info['code'] not in source_code_snippets_seen:
                all_found_sources.append(source_info)
                source_code_snippets_seen.add(source_info['code'])
    
    # Step 4: parse the AST only when needed for the fallback
    so_path = TREE_SITTER_SO_PATH
    LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(bytes(function_code, "utf8"))
    root_node = tree.root_node
    
    # Strategy 2: Fallback - if no high-quality Source was found, look for the declaration
    if not all_found_sources:
        # We must now find the declaration of *any* variable in taint_alias_set
        # (this logic is borrowed from analyze_taint_paths)
        query_string = f"""(identifier) @variable"""
        query = LANGUAGE.query(query_string)
        captures = query.captures(root_node)
        
        # Filter identifiers, keeping only those in the alias set
        variable_nodes = [node for node, tag in captures if node.text.decode('utf8') in taint_alias_set]

        for node in variable_nodes:
            statement_node = _get_enclosing_statement(node)
            if not statement_node or statement_node.type != 'declaration':
                continue

            # Confirm this *is* the identifier's declaration
            for declarator in statement_node.children:
                # Fix: a plain `int i;` declaration exposes the variable as a
                # bare identifier child, not a *declarator node; accept it too.
                if 'declarator' in declarator.type or declarator.type == 'identifier':
                    q_decl = [declarator]
                    found_id_node = None
                    while q_decl:
                        curr = q_decl.pop(0)
                        if curr.type == 'identifier':
                            found_id_node = curr
                            break
                        q_decl.extend(curr.children)

                    if found_id_node == node:
                        # Found! This is the declaration
                        code_snippet = statement_node.text.decode('utf8').strip().replace('\n', ' ')
                        if code_snippet not in source_code_snippets_seen:
                            fallback_source_info = {
                                "code": code_snippet,
                                "source_from_function": "" # declaration
                            }
                            all_found_sources.append(fallback_source_info)
                            source_code_snippets_seen.add(code_snippet)
                        break # found this node's declaration; exit the declarator loop
    
    # --- [NEW] Step 5: final exit point ---
    if not all_found_sources:
        # Neither a high-quality Source nor a declaration Source
        return {"path_segments": []}

    # Step 6: find Sinks (using the parsed tree)
    variable_c_type = _get_variable_c_type(root_node, variable_name)
    found_sinks_map = {}
    q = deque([root_node])
    
    while q:
        node = q.popleft()
        
        if node.type == 'identifier' and node.text.decode('utf8') in taint_alias_set:
            
            sink_info = _classify_sink(node, variable_c_type)
            
            if sink_info:
                category, sink_node = sink_info
                
                statement_node = _get_enclosing_statement(sink_node)
                if not statement_node: statement_node = sink_node

                # (applying our earlier fix: smart extraction of if(condition))
                code_snippet = None
                control_flow_types = {"if_statement", "while_statement", "for_statement", "switch_statement"}

                if statement_node.type in control_flow_types:
                    condition_node = statement_node.child_by_field_name('condition')
                    if condition_node and \
                       sink_node.start_byte >= condition_node.start_byte and \
                       sink_node.end_byte <= condition_node.end_byte:
                        
                        keyword_node = statement_node.child(0)
                        keyword_text = keyword_node.text.decode('utf8') if keyword_node else statement_node.type.split('_')[0]

                        if statement_node.type == 'for_statement':
                            body_node = statement_node.child_by_field_name('body')
                            l_paren = statement_node.child(1)
                            r_paren = body_node.prev_sibling if body_node else statement_node.last_named_child
                            if l_paren and r_paren and l_paren.type == '(':
                                # node.text is relative to the node; slice with relative offsets.
                                control_content_bytes = statement_node.text[
                                    l_paren.start_byte - statement_node.start_byte:
                                    r_paren.end_byte - statement_node.start_byte
                                ]
                                control_content_text = control_content_bytes.decode('utf8')
                                code_snippet = f"for {control_content_text}"
                            else:
                                code_snippet = f"for ({condition_node.text.decode('utf8')})"
                        else:
                            code_snippet = f"{keyword_text} ({condition_node.text.decode('utf8')})"
                
                if code_snippet is None:
                    code_snippet = statement_node.text.decode('utf8').strip().replace('\n', ' ')
                # --- (end of fix) ---

                # --- [MODIFIED] check against *any* known Source ---
                if code_snippet in source_code_snippets_seen:
                    # Keep dereferences of a tainted alias even when the same
                    # statement is also the source (e.g. CVE-2009-1897:
                    # `struct sock *sk = tun->sk;` is source AND deref sink).
                    if not _statement_has_tainted_deref(statement_node, taint_alias_set):
                        continue
                if statement_node.start_byte in found_sinks_map:
                    continue

                controls = _find_control_dependencies(sink_node)

                found_sinks_map[statement_node.start_byte] = {
                    "code": code_snippet,
                    "category": category,
                    "control_dependence": controls,
                    # [SHADOW] structured guard/event facts: purely additive fields, existing logic untouched
                    "guard_facts": _find_control_guard_facts(sink_node),
                    "event_sequence": sink_event_sequence(
                        function_code, statement_node.start_byte,
                        taint_alias_set, canonical_object=variable_name,
                        primary_var=variable_name),
                    "start_byte": statement_node.start_byte,
                }

        if node.children:
            q.extend(node.children)

    # Step 7: assemble the final result
    final_sinks_list = list(found_sinks_map.values())
    final_sinks_list.extend(
        _bound_controlled_index_sinks(
            root_node, function_code, set(taint_alias_set)
        )
    )
    final_sinks_list.extend(
        _scalar_field_flow_sinks(
            root_node, function_code, set(taint_alias_set), variable_c_type
        )
    )
    
    if not final_sinks_list:
        return {"path_segments": []}

    final_segment = {
        "source_variable": sorted(list(taint_alias_set)),
        "source_type": variable_c_type, 
        "taint_source": [s['code'] for s in all_found_sources],
        "source_from_function": [s['source_from_function'] for s in all_found_sources],
        "sinks": final_sinks_list,
        "analysis_summary": {
            "alias_set_size": len(taint_alias_set),
            "source_count": len(all_found_sources),
            "sink_count": len(final_sinks_list),
            "source_strategy": "high_quality_then_declaration_fallback",
        },
    }
    return final_segment


def analyze_taint_paths_by_param_index(function_code: str, param_index: int, language: str = 'c'):
    """
    [Refactored - key fixes]
    Implements the hybrid Source strategy:
    1. The function parameter entry is always the first Source.
    2. Append any other high-value Sources found by _pre_analyze_and_build_context.
    """
    so_path = TREE_SITTER_SO_PATH
    LANGUAGE = Language(so_path, language)
    parser = Parser()
    parser.set_language(LANGUAGE)
    tree = parser.parse(bytes(function_code, "utf8"))
    root_node = tree.root_node

    # Step 1: get parameter info
    param_info = get_parameter_info(root_node, param_index)
    if not param_info or not param_info.get("name"):
        return {"path_segments": []}
    
    variable_name = param_info["name"]
    variable_c_type = param_info["type"]
    
    # Step 2: run the pre-analysis
    try:
        context = _pre_analyze_and_build_context(function_code, language)
        uf = context["union_find"]
        high_quality_sources = context["sources"]
    except Exception as e:
        print(f"[Error] During pre-analysis phase: {e}")
        return {"path_segments": []}
        
    if variable_name not in uf.parent:
        uf.parent[variable_name] = variable_name
        uf.size[variable_name] = 1

    _propagate_parameter_dependencies(uf, root_node, variable_name)
    taint_alias_set = uf.get_set(variable_name)
    
    # --- [NEW] Step 3: hybrid Source lookup ---
    all_found_sources = []
    source_code_snippets_seen = set() # for dedup

    # Strategy 1: function entry (preferred)
    func_declarator_node = root_node.child_by_field_name('declarator')
    taint_source_code = func_declarator_node.text.decode('utf8') if func_declarator_node else ""
    entry_source_info = {"code": f"Function parameter: {taint_source_code}", "source_from_function": "[Function Entry]"}
    all_found_sources.append(entry_source_info)
    source_code_snippets_seen.add(entry_source_info['code'])
    
    # Strategy 2: find other high-quality Sources (appended)
    for var in taint_alias_set:
        if var in high_quality_sources:
            source_info = high_quality_sources[var]
            if source_info['code'] not in source_code_snippets_seen:
                all_found_sources.append(source_info)
                source_code_snippets_seen.add(source_info['code'])
    
    # The fallback strategy (declaration lookup) is unneeded here: a "Function parameter" source is guaranteed

    # Step 4: find Sinks
    found_sinks_map = {}
    q = deque([root_node])
    
    while q:
        node = q.popleft()
        if node.type == 'identifier' and node.text.decode('utf8') in taint_alias_set:
            
            sink_info = _classify_sink(node, variable_c_type)
            
            if sink_info:
                category, sink_node = sink_info
                
                statement_node = _get_enclosing_statement(sink_node)
                if not statement_node: statement_node = sink_node
                
                # (applying our earlier fix: smart extraction of if(condition))
                code_snippet = None
                control_flow_types = {"if_statement", "while_statement", "for_statement", "switch_statement"}

                if statement_node.type in control_flow_types:
                    condition_node = statement_node.child_by_field_name('condition')
                    if condition_node and \
                       sink_node.start_byte >= condition_node.start_byte and \
                       sink_node.end_byte <= condition_node.end_byte:
                        
                        keyword_node = statement_node.child(0)
                        keyword_text = keyword_node.text.decode('utf8') if keyword_node else statement_node.type.split('_')[0]

                        if statement_node.type == 'for_statement':
                            body_node = statement_node.child_by_field_name('body')
                            l_paren = statement_node.child(1)
                            r_paren = body_node.prev_sibling if body_node else statement_node.last_named_child
                            if l_paren and r_paren and l_paren.type == '(':
                                # node.text is relative to the node; slice with relative offsets.
                                control_content_bytes = statement_node.text[
                                    l_paren.start_byte - statement_node.start_byte:
                                    r_paren.end_byte - statement_node.start_byte
                                ]
                                control_content_text = control_content_bytes.decode('utf8')
                                code_snippet = f"for {control_content_text}"
                            else:
                                code_snippet = f"for ({condition_node.text.decode('utf8')})"
                        else:
                            code_snippet = f"{keyword_text} ({condition_node.text.decode('utf8')})"
                
                if code_snippet is None:
                    code_snippet = statement_node.text.decode('utf8').strip().replace('\n', ' ')
                # --- (end of fix) ---

                # --- [MODIFIED] check against *any* known Source ---
                if code_snippet in source_code_snippets_seen:
                    # Same deref exemption as analyze_taint_paths.
                    if not _statement_has_tainted_deref(statement_node, taint_alias_set):
                        continue
                if statement_node.start_byte in found_sinks_map:
                    continue

                controls = _find_control_dependencies(sink_node)

                found_sinks_map[statement_node.start_byte] = {
                    "code": code_snippet,
                    "category": category,
                    "control_dependence": controls,
                    # [SHADOW] structured guard/event facts: purely additive fields, existing logic untouched
                    "guard_facts": _find_control_guard_facts(sink_node),
                    "event_sequence": sink_event_sequence(
                        function_code, statement_node.start_byte,
                        taint_alias_set, canonical_object=variable_name,
                        primary_var=variable_name),
                    "start_byte": statement_node.start_byte,
                }

        if node.children:
            q.extend(node.children)

    # Step 5: assemble the result
    final_sinks_list = list(found_sinks_map.values())
    final_sinks_list.extend(
        _bound_controlled_index_sinks(
            root_node, function_code, set(taint_alias_set)
        )
    )
    final_sinks_list.extend(
        _scalar_field_flow_sinks(
            root_node, function_code, set(taint_alias_set), variable_c_type
        )
    )
    
    if not final_sinks_list:
        return {"path_segments": []}
        
    final_segment = {
        "source_variable": sorted(list(taint_alias_set)),
        "source_type": variable_c_type,
        # --- [MODIFIED] use all_found_sources ---
        "taint_source": [s['code'] for s in all_found_sources],
        "source_from_function": [s['source_from_function'] for s in all_found_sources],
        "sinks": final_sinks_list,
        "analysis_summary": {
            "alias_set_size": len(taint_alias_set),
            "source_count": len(all_found_sources),
            "sink_count": len(final_sinks_list),
            "source_strategy": "function_entry_plus_high_quality_sources",
        },
    }
    return final_segment

# --- 4. Usage example ---
# =============================================================================
# RECALL-PRESERVING ADDITIVE OPTIMIZATIONS
# =============================================================================
# The original dataflow implementation above is intentionally retained. The
# code below only adds: (1) immutable caching wrappers, (2) kernel integer type
# aliases, (3) compound-update/control-use facts, (4) a parallel lightweight
# lifecycle path, and (5) relevant macro extraction.

from functools import lru_cache as _lru_cache
from typing import Optional as _Optional

# Linux/kernel and common project typedefs. This only broadens the set of
# variables analyzed; it does not remove or reinterpret any original type.
INTEGER_KEYWORDS.update({
    'u8', 'u16', 'u32', 'u64', 's8', 's16', 's32', 's64',
    '__u8', '__u16', '__u32', '__u64', '__s8', '__s16', '__s32', '__s64',
    '__be16', '__be32', '__be64', '__le16', '__le32', '__le64',
    'sector_t', 'dma_addr_t', 'resource_size_t', 'gfp_t', 'umode_t',
})

# --- Safe immutable caches ---------------------------------------------------
# Cache only deterministic parse-derived values and recreate mutable UnionFind
# objects for each caller. This avoids changing analysis semantics.

@_lru_cache(maxsize=128)
def _cached_file_graph_data(file_path: str, language: str = 'c'):
    return _parse_file_and_build_graph_data_uncached(file_path, language)

def _parse_file_and_build_graph_data(file_path: str, language: str = 'c'):
    return _cached_file_graph_data(file_path, language)

@_lru_cache(maxsize=128)
def _cached_function_code_items(file_path: str, language: str = 'c'):
    defined_funcs_map, _, _, _ = _cached_file_graph_data(file_path, language)
    return tuple(
        (name, node.text.decode('utf-8', errors='ignore'))
        for name, node in defined_funcs_map.items()
    )

def get_code_from_file(function_name, file_path, language='c'):
    return dict(_cached_function_code_items(file_path, language)).get(function_name)

def get_funcnames_from_file(file_path, language='c'):
    return [name for name, _ in _cached_function_code_items(file_path, language)]

@_lru_cache(maxsize=512)
def _cached_extract_filtered_local_variables(function_code: str, language: str = 'c'):
    return tuple(_extract_filtered_local_variables_uncached(function_code, language))

def extract_filtered_local_variables(function_code: str, language: str = 'c') -> list[str]:
    return list(_cached_extract_filtered_local_variables(function_code, language))

@_lru_cache(maxsize=256)
def _cached_preanalysis_snapshot(function_code: str, language: str = 'c'):
    context = _pre_analyze_and_build_context_uncached(function_code, language)
    uf = context['union_find']
    groups_map: dict[str, list[str]] = {}
    for element in uf.parent:
        root = uf.find(element)
        groups_map.setdefault(root, []).append(element)
    groups = tuple(tuple(sorted(group)) for group in groups_map.values())
    sources = tuple(
        sorted(
            (name, info.get('code', ''), info.get('source_from_function', ''))
            for name, info in context.get('sources', {}).items()
        )
    )
    return groups, sources

def _pre_analyze_and_build_context(function_code: str, language: str = 'c') -> dict:
    groups, source_rows = _cached_preanalysis_snapshot(function_code, language)
    elements = [item for group in groups for item in group]
    uf = UnionFind(elements)
    for group in groups:
        if not group:
            continue
        base = group[0]
        for item in group[1:]:
            uf.union(base, item)
    sources = {
        name: {'code': code, 'source_from_function': source_func}
        for name, code, source_func in source_rows
    }
    return {'union_find': uf, 'sources': sources}

# --- Additive integer facts --------------------------------------------------
def _node_text(node: Node | None) -> str:
    if node is None:
        return ''
    try:
        return node.text.decode('utf8', errors='ignore')
    except Exception:
        return ''

def _is_integer_type_text(variable_c_type: str) -> bool:
    if '*' in variable_c_type or '[' in variable_c_type:
        return False
    tokens = set(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', variable_c_type or ''))
    return bool(tokens.intersection(INTEGER_KEYWORDS))

def _assignment_operator(parent: Node) -> str:
    # Tree-sitter C commonly exposes the operator as the unnamed child between
    # left and right. Text fallback keeps this compatible across bindings.
    left = parent.child_by_field_name('left')
    right = parent.child_by_field_name('right')
    if left is not None and right is not None:
        try:
            middle = parent.text[left.end_byte - parent.start_byte:right.start_byte - parent.start_byte]
            op = middle.decode('utf8', errors='ignore').strip()
            if op:
                return op
        except Exception:
            pass
    text = _node_text(parent)
    match = re.search(r'(<<=|>>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|=)', text)
    return match.group(1) if match else ''

def _integer_control_ancestor(node: Node) -> Node | None:
    current = node
    while current is not None and current.type != 'function_definition':
        if current.type in {'if_statement', 'while_statement', 'for_statement', 'do_statement'}:
            condition = current.child_by_field_name('condition')
            if condition is not None and node.start_byte >= condition.start_byte and node.end_byte <= condition.end_byte:
                return condition
        current = current.parent
    return None

def _classify_sink(node: Node, variable_c_type: str) -> tuple[str, Node] | None:
    parent = node.parent
    if parent is not None and _is_integer_type_text(variable_c_type):
        if parent.type == 'assignment_expression' and parent.child_by_field_name('left') == node:
            operator = _assignment_operator(parent)
            if operator and operator != '=':
                return 'Integer Arithmetic', parent
        if parent.type == 'update_expression':
            return 'Integer Arithmetic', parent

    original = _classify_sink_base(node, variable_c_type)
    if original is not None:
        return original

    if _is_integer_type_text(variable_c_type):
        condition = _integer_control_ancestor(node)
        if condition is not None:
            return 'Integer Control Use', condition
    return None

# --- Cached source text / parser helpers ------------------------------------
@_lru_cache(maxsize=128)
def _read_source_cached(file_path: str) -> str:
    with open(file_path, 'r', encoding='utf8') as handle:
        return handle.read()

@_lru_cache(maxsize=8)
def _language_cached(language: str = 'c'):
    return Language(TREE_SITTER_SO_PATH, language)

@_lru_cache(maxsize=256)
def _function_tree_cached(function_code: str, language: str = 'c'):
    parser = Parser()
    parser.set_language(_language_cached(language))
    return parser.parse(function_code.encode('utf8'))

# --- Macro context -----------------------------------------------------------
@_lru_cache(maxsize=128)
def _macro_definition_index(file_path: str) -> tuple[tuple[str, str], ...]:
    """Parse all #define blocks once per file and preserve source order."""
    try:
        source_code = _read_source_cached(file_path)
    except Exception:
        return tuple()

    lines = source_code.splitlines()
    definitions: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r'\s*#\s*define\s+([A-Za-z_]\w*)', line)
        if not match:
            index += 1
            continue
        name = match.group(1)
        block = [line]
        while block[-1].rstrip().endswith('\\') and index + 1 < len(lines):
            index += 1
            block.append(lines[index])
        definitions.append((name, '\n'.join(block)))
        index += 1
    return tuple(definitions)


def extract_relevant_macro_definitions(
    file_path: str,
    relevant_text: str,
    max_definitions: int | None = None,
    max_chars: int | None = None,
) -> dict[str, str]:
    """Select referenced macros from a cached per-file definition index."""
    tokens = set(re.findall(r'\b[A-Z_][A-Z0-9_]{1,}\b', relevant_text or ''))
    for marker in ('GROW', 'SHRINK', 'NEXT', 'NEXTL', 'CUR_CHAR', 'CUR_PTR', 'BASE_PTR'):
        if re.search(rf'\b{re.escape(marker)}\b', relevant_text or ''):
            tokens.add(marker)

    definitions: dict[str, str] = {}
    total = 0
    for name, definition in _macro_definition_index(file_path):
        if max_definitions is not None and len(definitions) >= max_definitions:
            break
        relevant = name in tokens or any(word in name.upper() for word in ('GROW', 'RESIZE', 'REALLOC', 'FREE'))
        if relevant and (max_chars is None or total + len(definition) <= max_chars):
            definitions[name] = definition
            total += len(definition)
    return definitions


def _declaration_names(node, text: str) -> set[str]:
    """Return identifiers introduced by one top-level support declaration."""
    if node.type in {'preproc_def', 'preproc_function_def'}:
        match = re.match(r'\s*#\s*define\s+([A-Za-z_]\w*)', text)
        return {match.group(1)} if match else set()

    def declarator_names(current) -> set[str]:
        if current is None:
            return set()
        if current.type in {'identifier', 'type_identifier', 'field_identifier'}:
            return {_node_text(current)}
        nested = current.child_by_field_name('declarator')
        if nested is not None and nested != current:
            return declarator_names(nested)
        names: set[str] = set()
        for child in current.named_children:
            if child.type == 'initializer_list':
                continue
            if (
                'declarator' in child.type
                or child.type in {'identifier', 'type_identifier', 'field_identifier'}
            ):
                names.update(declarator_names(child))
        return names

    names = declarator_names(node.child_by_field_name('declarator'))
    if node.type in {'struct_specifier', 'union_specifier', 'enum_specifier'}:
        name_node = node.child_by_field_name('name')
        if name_node is not None:
            names.add(_node_text(name_node))
    if node.type == 'type_definition':
        for child in node.named_children:
            if child.type in {'type_identifier', 'identifier'}:
                names.add(_node_text(child))
    return {name for name in names if name}


@_lru_cache(maxsize=128)
def _declaration_definition_index(
    file_path: str,
) -> tuple[tuple[tuple[str, ...], str], ...]:
    """Index top-level non-function definitions once per synthesized source."""
    try:
        source_code = _read_source_cached(file_path)
        suffix = os.path.splitext(file_path)[1].lower()
        language = (
            'cpp'
            if suffix in {'.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx'}
            else 'c'
        )
        tree = _function_tree_cached(source_code, language)
    except Exception:
        return tuple()

    allowed = {
        'type_definition', 'struct_specifier', 'union_specifier',
        'enum_specifier', 'declaration',
    }
    entries: list[tuple[tuple[str, ...], str]] = []
    for node in tree.root_node.named_children:
        if node.type not in allowed:
            continue
        text = _node_text(node).strip()
        names = _declaration_names(node, text)
        if names and text:
            entries.append((tuple(sorted(names)), text))
    return tuple(entries)


def extract_relevant_declarations(
    file_path: str,
    relevant_text: str,
    max_chars: int | None = None,
) -> dict[str, str]:
    """Select a bounded transitive closure of referenced type/global definitions."""
    referenced = set(re.findall(r'\b[A-Za-z_]\w*\b', relevant_text or ''))
    entries = _declaration_definition_index(file_path)
    selected: dict[str, str] = {}
    selected_indices: set[int] = set()
    total = 0
    changed = True
    while changed:
        changed = False
        for index, (names, definition) in enumerate(entries):
            if index in selected_indices or not (set(names) & referenced):
                continue
            if max_chars is not None and total + len(definition) > max_chars:
                continue
            selected_indices.add(index)
            key = next((name for name in names if name in referenced), names[0])
            selected[f'{key}@{index}'] = definition
            total += len(definition)
            referenced.update(re.findall(r'\b[A-Za-z_]\w*\b', definition))
            changed = True
    return selected

# --- Object-centric lifecycle facts -----------------------------------------

# Same-file macro bodies make growth/release semantics visible to the lifecycle
# engine: `GROW;` alone carries no invalidation target, but its #define body
# references ctxt->input->end/cur and calls xmlGROW(ctxt). Expansion is used for
# event recognition only; original statement text is always kept for display.
_MACRO_BODY_MAX_CHARS = 600
_MACRO_EXPAND_MAX_CHARS = 1500


def collect_macro_definitions(file_code: str) -> dict[str, dict[str, Any]]:
    """Collect simple same-file #define bodies for lifecycle event recognition.

    Returns name -> {'params': list[str] | None, 'body': str}. Bodies that are
    too long or contain preprocessor directives are skipped; this is a
    best-effort single-pass expander, not a C preprocessor.
    """
    macros: dict[str, dict[str, Any]] = {}
    if not file_code:
        return macros
    # Join backslash-continued lines so multi-line macro bodies are one string.
    joined = re.sub(r'\\\r?\n', ' ', file_code)
    for match in re.finditer(
        r'^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\(([^)]*)\))?[ \t]*(.*)$',
        joined,
        flags=re.M,
    ):
        name = match.group(1)
        params_text = match.group(3)
        body = (match.group(4) or '').strip()
        if not body or len(body) > _MACRO_BODY_MAX_CHARS or '#' in body:
            continue
        params: list[str] | None = None
        if params_text is not None:
            params = [item.strip() for item in params_text.split(',') if item.strip()]
            if any(not re.fullmatch(r'[A-Za-z_]\w*', item) for item in params):
                continue  # variadic or exotic parameter lists: skip
        macros[name] = {'params': params, 'body': body}
    return macros


_LIFECYCLE_MACRO_CACHE: dict[str, dict[str, dict[str, Any]]] = {}


def collect_macro_definitions_for_file(file_path: str) -> dict[str, dict[str, Any]]:
    """Per-file cached variant of collect_macro_definitions (engine entry point)."""
    cached = _LIFECYCLE_MACRO_CACHE.get(file_path)
    if cached is None:
        try:
            text = _read_source_cached(file_path)
        except Exception:
            text = ''
        cached = collect_macro_definitions(text)
        _LIFECYCLE_MACRO_CACHE[file_path] = cached
    return cached


def expand_macro_statement(
    code: str,
    macro_defs: dict[str, dict[str, Any]] | None,
    max_passes: int = 2,
) -> str:
    """Best-effort expansion of macros in one statement, for analysis only."""
    if not macro_defs or not code:
        return code or ''
    expanded = code
    for _ in range(max_passes):
        changed = False
        for name, spec in macro_defs.items():
            params = spec.get('params')
            body = spec.get('body') or ''
            if params is None:
                if re.search(rf'\b{re.escape(name)}\b(?!\s*\()', expanded):
                    expanded = re.sub(
                        rf'\b{re.escape(name)}\b(?!\s*\()', body, expanded,
                    )
                    changed = True
                continue
            for call in re.finditer(rf'\b{re.escape(name)}\s*\(', expanded):
                open_paren = call.end() - 1
                depth = 0
                close = -1
                for index in range(open_paren, len(expanded)):
                    char = expanded[index]
                    if char == '(':
                        depth += 1
                    elif char == ')':
                        depth -= 1
                        if depth == 0:
                            close = index
                            break
                if close < 0:
                    continue
                args = _split_call_args(expanded[open_paren + 1:close])
                if len(args) != len(params):
                    continue
                substituted = body
                for param, arg in zip(params, args):
                    substituted = re.sub(
                        rf'\b{re.escape(param)}\b', arg.strip() or '0', substituted,
                    )
                expanded = expanded[:call.start()] + substituted + expanded[close + 1:]
                changed = True
                break  # positions shifted; rescan this macro on the next pass
            if len(expanded) > _MACRO_EXPAND_MAX_CHARS:
                return expanded[:_MACRO_EXPAND_MAX_CHARS]
        if not changed:
            break
    return expanded[:_MACRO_EXPAND_MAX_CHARS]


def _split_call_args(argument_text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote = ''
    for index, char in enumerate(argument_text):
        if quote:
            if char == quote and argument_text[index - 1] != '\\':
                quote = ''
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == ',' and depth == 0:
            parts.append(argument_text[start:index])
            start = index + 1
    parts.append(argument_text[start:])
    return parts


def _normalize_lvalue(text: str) -> str:
    text = (text or '').strip()
    text = re.sub(r'^[\s\*&()]+', '', text)
    text = re.sub(r'\[[^\]]*\]$', '', text)
    return text.strip()


def _abstract_backing_object(expression: str) -> _Optional[str]:
    expression = expression or ''
    field = re.search(
        r'([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*(?:->|\.)\s*'
        r'(cur|base|end|data|buf|buffer|content|storage)\b',
        expression,
    )
    if field:
        return f"{field.group(1)}::buffer"
    array = re.search(r'\b([A-Za-z_]\w*)\s*\[', expression)
    if array:
        return f"{array.group(1)}::storage"
    return None


def _lifecycle_statements(function_code: str, language: str = 'c') -> list[dict[str, Any]]:
    tree = _function_tree_cached(function_code, language)
    wanted = {'expression_statement', 'declaration', 'return_statement'}
    # Calls and dereferences inside control-flow conditions are lifecycle-
    # relevant too: `if (!BUF_MEM_grow_clean(buf, n))` is a growth event and
    # `if (!PACKET_buf_init(&pkt, s->init_msg, len))` is a pointer-consuming
    # use, but neither is an expression_statement.
    condition_parents = {'if_statement', 'while_statement', 'for_statement', 'do_statement'}
    records: list[dict[str, Any]] = []
    queue = deque([tree.root_node])
    while queue:
        node = queue.popleft()
        if node.type in wanted:
            code = re.sub(r'\s+', ' ', _node_text(node).strip())
            controls = _find_control_dependencies(node)
            records.append({
                'node': node,
                'code': code,
                'start_byte': node.start_byte,
                'controls': controls,
                'branch_signature': _branch_signature(controls),
            })
            continue
        if node.type in condition_parents:
            condition = node.child_by_field_name('condition')
            if condition is not None:
                relevant = False
                scan = [condition]
                interesting = {
                    'call_expression', 'field_expression', 'pointer_expression',
                    'subscript_expression', 'assignment_expression', 'update_expression',
                }
                while scan and not relevant:
                    current = scan.pop()
                    if current.type in interesting:
                        relevant = True
                        break
                    scan.extend(current.children)
                code = re.sub(r'\s+', ' ', _node_text(condition).strip())
                if code and relevant:
                    controls = _find_control_dependencies(node)
                    records.append({
                        'node': node,
                        'code': code,
                        'start_byte': condition.start_byte,
                        'controls': controls,
                        'branch_signature': _branch_signature(controls),
                    })
        queue.extend(node.children)
    records.sort(key=lambda item: _safe_int(item.get('start_byte'), 0))
    return records


def _simple_assignment(code: str) -> _Optional[tuple[str, str]]:
    # Parse member lvalues before the declaration-oriented fallback. These
    # assignments establish aliases into movable backing storage.
    member_match = re.search(
        r'^\s*([*]*[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)+)\s*=\s*([^=].*?);?$',
        code or '',
    )
    if member_match:
        raw_lhs = member_match.group(1)
        if raw_lhs.lstrip().startswith('*'):
            # `*p->f = v` (i.e. `*(p->f) = v`) writes through the field pointer;
            # it does not rebind the field path itself.
            return None
        return (
            _normalize_lvalue(raw_lhs),
            member_match.group(2).strip().rstrip(';'),
        )

    # Supports declarations and simple assignments while excluding comparisons.
    match = re.search(
        r'(?:^|[;{}])?\s*(?P<decl>[A-Za-z_][\w\s]*\s+)?(?P<lhs>[*]*[A-Za-z_]\w*)\s*=\s*([^=].*?);?$',
        code or '',
    )
    if not match:
        return None
    raw_lhs = match.group('lhs')
    if raw_lhs.startswith('*') and not match.group('decl'):
        # `*p = v` writes through p (a pointee write / strong use of p), not a
        # reassignment of p: p keeps pointing to the same object, so aliases,
        # invalidations and at-risk state for p must survive. A leading star in
        # a declaration (`int *p = x`) is a declarator and still binds p.
        return None
    return _normalize_lvalue(raw_lhs), match.group(3).strip().rstrip(';')


def _release_event(code: str) -> _Optional[tuple[str, str]]:
    match = re.search(
        r'\b(free|xmlFree|kfree|g_free|xfree|OPENSSL_free)\s*\(\s*([^,;)]+)',
        code or '',
        flags=re.I,
    )
    if match:
        return match.group(1), _normalize_lvalue(match.group(2))
    delete_match = re.search(r'\bdelete(?:\s*\[\s*\])?\s+([A-Za-z_]\w*)', code or '')
    if delete_match:
        return 'delete', delete_match.group(1)
    return None


def _growth_event(code: str) -> _Optional[str]:
    direct = re.search(
        r'\b(realloc|xmlRealloc|g_realloc|krealloc|OPENSSL_realloc)\s*\(',
        code or '',
        flags=re.I,
    )
    if direct:
        return direct.group(1)
    for match in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', code or ''):
        function_name = match.group(1)
        if any(
            marker in function_name.lower()
            for marker in ('grow', 'resize', 'realloc', 'expand', 'reserve')
        ):
            return function_name
    macro = re.search(r'\b(GROW|SHRINK|RESIZE|EXPAND|REALLOC)\b', code or '')
    return macro.group(1) if macro else None


def _pointer_consuming_use(code: str, variable: str) -> bool:
    escaped = re.escape(variable)
    return bool(
        re.search(rf'\*\s*{escaped}\b|\b{escaped}\s*->|\b{escaped}\s*\[', code)
        or re.search(rf'\b{escaped}\b\s*[+\-]|[+\-]\s*\b{escaped}\b', code)
        or re.search(rf'\b[A-Za-z_]\w*\s*\([^;]*\b{escaped}\b[^;]*\)', code)
        or re.search(rf'\breturn\b[^;]*\b{escaped}\b', code)
    )


def _pointer_use_strength(code: str, variable: str) -> str:
    """Strong uses touch the pointee (deref/member/subscript/arithmetic); passing
    the pointer to an opaque call or returning it is a weak use — it may be a
    read-only observation and ranks below strong uses for the observation cap."""
    escaped = re.escape(variable)
    if re.search(rf'\*\s*{escaped}\b|\b{escaped}\s*->|\b{escaped}\s*\[', code):
        return 'strong'
    if re.search(rf'\b{escaped}\b\s*[+\-]|[+\-]\s*\b{escaped}\b', code):
        return 'strong'
    return 'weak'


# Cross-call persistent field state (P2): a field of a non-local object (a
# parameter or another outliving structure) keeps referencing a released object
# because the field was never cleared. Pattern:
#   FIELD_REFERENCE   local alias / key-equivalent match ties the field to the object
#   RELEASE           the object is provably released through the local
#   FIELD_NOT_CLEARED no assignment to the field follows the release
#   (later use)       the field is dereferenced in this function, so any later
#                     call/re-entry on the same host object dereferences freed memory
# Identity caveat: a comparison like `pin->gpiod == rdev->ena_pin->gpiod` is only
# key-equivalent evidence — emitted as key_equivalent_alias, never as proven
# object identity.
_FIELD_DANGLING_OBS_ENABLED = os.environ.get('VUL_FIELD_DANGLING_OBS', '1').strip().lower() not in {'0', 'false', 'off'}


_LOCK_FLAG_RACE_OBS_ENABLED = os.environ.get('VUL_LOCK_FLAG_RACE_OBS', '1').strip().lower() not in {'0', 'false', 'off'}
_LOCK_ACQUIRE_RE = re.compile(
    r'\bspin_lock(?:_irqsave|_irq|_bh|_nested)?\s*\(\s*&?\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*[,)]'
)
_LOCK_RELEASE_RE = re.compile(
    r'\bspin_unlock(?:_irqrestore|_irq|_bh)?\s*\(\s*&?\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*[,)]'
)
_LOCK_FLAG_LIST_OP_RE = re.compile(r'\blist_(?:add|del|del_init|move)(?:_rcu|_tail)?\s*\(')
_LOCK_FLAG_IF_RE = re.compile(
    r'\bif\s*\(\s*!?\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*\)'
)


def _flex_path_pattern(path: str) -> str:
    """Regex for a field path with flexible whitespace around -> / ."""
    return r'\s*(?:->|\.)\s*'.join(re.escape(part) for part in re.split(r'->|\.', path))


def _lock_flag_race_observations(
    function_code: str,
    function_name: str,
) -> list[dict[str, Any]]:
    """Flag-guarded list operation where the flag is checked AND written outside
    the spin lock that guards the list operation (double-entry race anchor).

    Shape (CVE-2017-10661): ``if (ctx->might_cancel) { ctx->might_cancel = false;
    spin_lock(&cancel_lock); list_del_rcu(&ctx->clist); spin_unlock(&cancel_lock); }``
    — two concurrent executions can both observe the pre-write flag value and
    both perform the list operation. Observation-level anchor, not a verdict.
    """
    if not _LOCK_FLAG_RACE_OBS_ENABLED or not function_code:
        return []
    code = function_code
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    # All lock regions in this function, grouped by lock object: flag accesses
    # already covered by an outer lock (e.g. the patched CVE-2017-10661
    # timerfd_setup_cancel holds ctx->cancel_lock across the body) are
    # serialized and must not anchor a race.
    all_regions: dict[str, list[tuple[int, int]]] = {}
    for _lm in _LOCK_ACQUIRE_RE.finditer(code):
        _obj = re.sub(r'\s+', '', _lm.group(1))
        for _um in _LOCK_RELEASE_RE.finditer(code, _lm.end()):
            if re.sub(r'\s+', '', _um.group(1)) == _obj:
                all_regions.setdefault(_obj, []).append((_lm.start(), _um.end()))
                break

    def _covered_by_same_lock(first: int, second: int) -> bool:
        for regions in all_regions.values():
            first_in = any(start <= first <= end for start, end in regions)
            second_in = any(start <= second <= end for start, end in regions)
            if first_in and second_in:
                return True
        return False

    for lock_match in _LOCK_ACQUIRE_RE.finditer(code):
        lock_obj = re.sub(r'\s+', '', lock_match.group(1))
        span_end = None
        for unlock in _LOCK_RELEASE_RE.finditer(code, lock_match.end()):
            if re.sub(r'\s+', '', unlock.group(1)) == lock_obj:
                span_end = unlock.end()
                break
        if span_end is None:
            continue
        span = code[lock_match.start():span_end]
        list_op = _LOCK_FLAG_LIST_OP_RE.search(span)
        if list_op is None:
            continue
        # Nearest controlling `if (<flag>)` before the lock region.
        prefix_start = max(0, lock_match.start() - 600)
        prefix = code[prefix_start:lock_match.start()]
        if_matches = list(_LOCK_FLAG_IF_RE.finditer(prefix))
        if not if_matches:
            continue
        if_match = if_matches[-1]
        flag = re.sub(r'\s+', '', if_match.group(1))
        # The flag must be written between the check and the lock (outside it).
        between = prefix[if_match.start():]
        write_match = re.search(
            _flex_path_pattern(flag) + r'\s*=\s*(?:true|false|0|1)\s*;',
            between,
        )
        if write_match is None:
            continue
        key = (flag, lock_obj, re.sub(r'\s+', ' ', list_op.group(0)))
        if key in seen:
            continue
        seen.add(key)
        if_abs = prefix_start + if_match.start()
        write_abs = prefix_start + if_match.start() + write_match.start()
        list_abs = lock_match.start() + list_op.start()
        if _covered_by_same_lock(if_abs, write_abs):
            # The flag check/write are already serialized by an outer lock.
            continue

        def _line_at(position: int) -> str:
            start = code.rfind('\n', 0, position) + 1
            end = code.find('\n', position)
            return code[start:end if end > 0 else len(code)].strip()

        def _event(kind: str, position: int, note: str) -> dict[str, Any]:
            return {
                'event_kind': kind,
                'code': _line_at(position),
                'controls': [],
                'branch_signature': [],
                'statement_index': code.count('\n', 0, position),
                'start_byte': position,
                'variable': flag,
                'alias_id': flag,
                'abstract_object': f'flag::{flag}',
                'object_id': f'flag::{flag}',
                'evidence_status': 'observation',
                'effect_source': note,
                'event_id': f'{kind}:{function_name}:{position}:{flag}',
            }

        candidates.append({
            'kind': 'lock_flag_race_suspect',
            'variable': flag,
            'object': f'flag::{flag}',
            'evidence_status': 'observation',
            'use_strength': 'strong',
            'events': [
                _event(
                    'FLAG_CHECK_OUTSIDE_LOCK', if_abs,
                    f'flag `{flag}` is checked WITHOUT holding `{lock_obj}`',
                ),
                _event(
                    'FLAG_WRITE_OUTSIDE_LOCK', write_abs,
                    f'flag `{flag}` is written WITHOUT holding `{lock_obj}`',
                ),
                _event(
                    'LIST_OP_UNDER_LOCK', list_abs,
                    f'the list operation this flag guards runs under `{lock_obj}`; '
                    'the flag check and write above are outside that lock, so two '
                    'concurrent executions on the same object can both observe the '
                    'pre-write value and both enter the locked region',
                ),
            ],
        })
    return candidates


def _field_dangling_observations(
    records: list[dict[str, Any]],
    function_code: str,
    function_name: str,
    language: str = 'c',
    caller_names: list[str] | None = None,
    externally_invoked: bool = False,
) -> list[dict[str, Any]]:
    if not _FIELD_DANGLING_OBS_ENABLED:
        return []
    try:
        local_vars = set(extract_filtered_local_variables(function_code, language) or [])
    except Exception:
        local_vars = set()

    # Released plain locals: kfree(pin) / free(x) / delete x.
    released: list[tuple[str, dict[str, Any]]] = []
    # Persistent field paths: base is not a local variable (parameter/heap host).
    persistent_fields: dict[str, dict[str, Any]] = {}
    # Comparison statements (candidate key-equivalence evidence).
    comparisons: list[dict[str, Any]] = []
    # Direct aliases: local = field (or field = local) assignments.
    direct_aliases: list[dict[str, Any]] = []
    # Field assignments anywhere (for the not-cleared check).
    field_writes: list[tuple[str, int]] = []
    # Field reads/uses (any appearance that is not a write to the field).
    field_uses: dict[str, dict[str, Any]] = {}

    field_re = re.compile(r'\b([A-Za-z_]\w*)\s*(->|\.)\s*([A-Za-z_]\w*)')

    for index, record in enumerate(records):
        record = {**record, 'statement_index': index}
        code = str(record.get('code') or '')
        if not code:
            continue
        release = _release_event(code)
        if release and release[1] and '->' not in release[1] and '.' not in release[1]:
            released.append((release[1], record))
        assignment = _simple_assignment(code)
        if assignment:
            lhs, rhs = assignment
            if '->' in lhs or '.' in lhs:
                field_writes.append((lhs, index))
                if re.fullmatch(r'[A-Za-z_]\w*', rhs or ''):
                    direct_aliases.append({'local': rhs, 'field': lhs, 'index': index, 'record': record})
            elif re.fullmatch(r'[A-Za-z_]\w*', lhs or '') and ('->' in rhs or '.' in rhs):
                direct_aliases.append({'local': lhs, 'field': _normalize_lvalue(rhs), 'index': index, 'record': record})
        if '==' in code or '!=' in code:
            comparisons.append(record)
        for match in field_re.finditer(code):
            base, accessor, field = match.group(1), match.group(2), match.group(3)
            if base in local_vars:
                continue
            path = f'{base}{accessor}{field}'
            persistent_fields.setdefault(path, record)
            # Any appearance that is not a write to the field itself counts as a
            # use: reads propagate the (possibly dangling) pointer on re-entry —
            # e.g. `iter = seqf->private` at the top of a re-callable stop hook.
            if assignment and assignment[0] == path:
                continue
            if re.search(rf'(?<![\w>]){re.escape(path)}', code):
                field_uses.setdefault(path, record)

    if not released or not persistent_fields:
        return []

    candidates: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for variable, release_record in released:
        release_index = _safe_int(release_record.get('statement_index'), -1)
        for field_path in persistent_fields:
            if (variable, field_path) in seen_pairs:
                continue
            identity = None
            evidence_record = None
            for alias in direct_aliases:
                if alias['local'] == variable and alias['field'] == field_path \
                        and alias['index'] < release_index:
                    identity = 'explicit'
                    evidence_record = alias['record']
                    break
            if identity is None:
                # Key-equivalent evidence: a comparison that dereferences the SAME
                # key K on both the released local and the persistent field path
                # (e.g. `pin->gpiod == rdev->ena_pin->gpiod`). This only suggests
                # the two refer to the same object — inferred, never proven.
                for cmp_record in comparisons:
                    if _safe_int(cmp_record.get('statement_index'), -1) > release_index:
                        continue
                    cmp_code = str(cmp_record.get('code') or '')
                    for key_match in re.finditer(
                        rf'\b{re.escape(variable)}\s*(?:->|\.)\s*([A-Za-z_]\w*)', cmp_code,
                    ):
                        key = key_match.group(1)
                        if re.search(
                            rf'{re.escape(field_path)}\s*(?:->|\.)\s*{re.escape(key)}\b',
                            cmp_code,
                        ):
                            identity = 'key_equivalent_alias'
                            evidence_record = cmp_record
                            break
                    if identity is not None:
                        break
            if identity is None:
                continue
            base = field_path.split('->', 1)[0].split('.', 1)[0]
            if variable == base:
                continue  # releasing the host itself is plain UAF, not field dangling
            # The field must not be cleared/replaced after the release.
            if any(write_index > release_index for path, write_index in field_writes if path == field_path):
                continue
            # If the host object itself is released after the referent, the field
            # dies with its host (destructor shape) — not a dangling field.
            if any(
                rel_var == base
                and _safe_int(rel_record.get('statement_index'), -1) > release_index
                for rel_var, rel_record in released
            ):
                continue
            # A later use must exist: the field is read/used in this function
            # (entry reads count — a re-entry on the same host object reads the
            # dangling field again, e.g. stop called after a failed start).
            use_record = field_uses.get(field_path)
            if use_record is None:
                continue
            seen_pairs.add((variable, field_path))
            object_id = f'field::{field_path}'
            ref_code = str(evidence_record.get('code') or '')
            if identity == 'key_equivalent_alias':
                ref_note = (
                    f'key-equivalent match in `{ref_code}`: the released local '
                    f'`{variable}` and the persistent field `{field_path}` identify the '
                    'same object by a compared key (inferred identity, not proven aliasing)'
                )
            else:
                ref_note = (
                    f'direct alias in `{ref_code}`: persistent field `{field_path}` '
                    f'references the same object as `{variable}`'
                )
            reference_event = {
                'event_kind': 'FIELD_REFERENCE',
                'code': ref_code,
                'controls': list(evidence_record.get('controls') or []),
                'branch_signature': list(evidence_record.get('branch_signature') or []),
                'statement_index': _safe_int(evidence_record.get('statement_index'), -1),
                'start_byte': _safe_int(evidence_record.get('start_byte'), -1),
                'variable': field_path,
                'alias_id': field_path,
                'abstract_object': object_id,
                'object_id': object_id,
                'effect_source': ref_note,
                'heuristic': identity != 'explicit',
                'event_id': f'FIELD_REFERENCE:{function_name}:{field_path}',
            }
            release_event = {
                'event_kind': 'RELEASE',
                'code': str(release_record.get('code') or ''),
                'controls': list(release_record.get('controls') or []),
                'branch_signature': list(release_record.get('branch_signature') or []),
                'statement_index': release_index,
                'start_byte': _safe_int(release_record.get('start_byte'), -1),
                'variable': variable,
                'alias_id': variable,
                'abstract_object': object_id,
                'object_id': object_id,
                'effect_source': 'direct',
                'event_id': f'RELEASE:{function_name}:{_safe_int(release_record.get("start_byte"), -1)}:{variable}',
            }
            not_cleared_event = {
                'event_kind': 'FIELD_NOT_CLEARED',
                'code': str(release_record.get('code') or ''),
                'controls': list(release_record.get('controls') or []),
                'branch_signature': list(release_record.get('branch_signature') or []),
                'statement_index': release_index,
                'start_byte': _safe_int(release_record.get('start_byte'), -1),
                'variable': field_path,
                'alias_id': field_path,
                'abstract_object': object_id,
                'object_id': object_id,
                'evidence_status': 'observation',
                'effect_source': (
                    f'no assignment to `{field_path}` follows this release in '
                    f'{function_name}; the field remains dangling, and it is '
                    f'read/used at `{str(use_record.get("code") or "")}` — any later '
                    'call/re-entry on the same host object uses the freed object'
                    + (
                        f'; {function_name} has {len(caller_names)} in-file call '
                        f'site(s) ({", ".join(caller_names[:4])}), and every invocation '
                        'reads the field at entry'
                        if caller_names else (
                            f'; {function_name} has no in-file call sites, so as '
                            'an entry point of the visible code unit it is invoked '
                            'from outside the supplied code, and every such '
                            'invocation reads the field at entry'
                            if externally_invoked else ''
                        )
                    )
                ),
                'ordering_note': (
                    f'analyzer ordering: the release of `{variable}` is not followed by '
                    f'any clear/replace of `{field_path}` in this function; the field '
                    f'persists on the non-local host `{base}` across calls'
                ),
                'event_id': f'FIELD_NOT_CLEARED:{function_name}:{field_path}',
            }
            candidates.append({
                'kind': 'field_dangling_suspect',
                'variable': field_path,
                'object': object_id,
                'evidence_status': 'observation',
                'effect_strength': 'summary_proven',
                'use_strength': 'strong',
                'object_identity': identity,
                'events': [reference_event, release_event, not_cleared_event],
            })
    return candidates


# Release-name hint used ONLY to raise heuristic observation anchors for the
# `Release(&x)` idiom (F3b) — never treated as proof of an effect; the verifier
# must still establish the effect under the P4 adjudication standard.
_RELEASE_HINT_CALLEE = re.compile(
    r'(?:free|destroy|delete|release|relinquish|unregister|cleanup|_put\b|_end\b)',
    flags=re.I,
)


# Lifecycle effect lattice for opaque statements (P1). Only visible bodies,
# in-file callee summaries, and standard allocator contracts are consulted;
# a callee's name alone never proves an effect. Statements whose expanded body
# contains a free-family call or a realloc-family growth are classified by the
# caller before reaching this point (they are real release/growth events, not
# opaque); this derivation therefore distinguishes only:
#   PROVEN_NO_EFFECT  every call in the (macro-expanded) statement resolves to
#                     an in-file summary with no release/invalidate effect, or
#                     the statement contains no calls at all
#   UNKNOWN           at least one external call with no in-file summary remains;
#                     the unresolved callees are named so downstream stages can
#                     target them instead of reasoning about an opaque statement
def _derive_statement_effect(
    analysis_code: str,
    callee_effects: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    unresolved: list[str] = []
    saw_call = False
    for callee, _args in _extract_calls(analysis_code or ''):
        saw_call = True
        summary = callee_effects.get(callee)
        if summary is not None:
            # In-file callee: the transitive summary was computed; an empty one
            # proves no release/reallocation effect on any argument.
            continue
        if _KNOWN_PURE_CALLEE.match(callee):
            continue
        unresolved.append(callee)
    if unresolved:
        return {
            'effect_kind': 'UNKNOWN',
            'provenance': 'unresolved',
            'unresolved': unresolved,
        }
    return {
        'effect_kind': 'PROVEN_NO_EFFECT',
        'provenance': 'callee_summary' if saw_call else 'direct_body',
        'unresolved': [],
    }


def detect_relocation_idioms(
    function_code: str,
    function_name: str = '',
    macro_defs: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Detect codebase self-defense against backing-storage relocation.

    Pattern: ``v = obj->field;`` ... intervening calls/macros ...
    ``if (obj->field != v) { corrective action }``. The codebase itself captures
    a buffer anchor and checks for relocation across the intervening operations
    (e.g. libxml2's ``base = ctxt->input->base`` + ``if (ctxt->input->base !=
    base) return htmlParseNameComplex(ctxt);``). This is file-local behavioral
    evidence that the intervening operations may relocate the backing storage —
    not a name-based guess.

    Returns a list of {'object', 'callees', 'site', 'capture', 'detail'}.
    """
    idioms: list[dict[str, Any]] = []
    if not function_code:
        return idioms
    lines = function_code.splitlines()
    offsets: list[int] = []
    cursor = 0
    for line in lines:
        offsets.append(cursor)
        cursor += len(line) + 1
    capture_re = re.compile(
        r'^\s*(?:[A-Za-z_][\w\s\*]*?\s)?(\*{0,2})([A-Za-z_]\w*)\s*=\s*'
        r'([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+)\s*;'
    )
    corrective_re = re.compile(r'\b(?:return|goto|continue|break)\b')
    seen: set[tuple[str, int]] = set()
    relocation_fields = {'base', 'data', 'buf', 'buffer', 'storage'}
    for index, line in enumerate(lines):
        capture = capture_re.match(line)
        if not capture:
            continue
        variable = capture.group(2)
        rhs = re.sub(r'\s+', '', capture.group(3))
        # Only anchor fields that witness relocation (base/data/...). A captured
        # cursor field (cur/end) checked for change proves cursor movement, not
        # relocation, and must not ground a MAY_RELOCATE upgrade.
        checked_field = re.split(r'->|\.', rhs)[-1]
        if checked_field not in relocation_fields:
            continue
        obj = _abstract_backing_object(rhs)
        if obj is None:
            continue
        limit = min(len(lines), index + 150)
        for probe in range(index + 1, limit):
            probe_line = lines[probe]
            if not re.search(r'\bif\s*\(', probe_line):
                continue
            condition = ' '.join(lines[probe:probe + 3])
            compact = re.sub(r'\s+', '', condition)
            compares = (
                f'{rhs}!={variable}' in compact
                or f'{variable}!={rhs}' in compact
                or f'{rhs}=={variable}' in compact
                or f'{variable}=={rhs}' in compact
            )
            if not compares:
                continue
            follow = '\n'.join(lines[probe:probe + 6])
            if not corrective_re.search(follow) and not re.search(
                rf'\b{re.escape(variable)}\s*=[^=]', follow
            ):
                continue
            window = expand_macro_statement(
                '\n'.join(lines[index:probe + 1]), macro_defs, max_passes=3,
            )
            callees = {name for name, _args in _extract_calls(window)}
            callees.discard(function_name)
            site = f'{function_name}@{offsets[probe]}'
            key = (obj, offsets[probe])
            if key in seen:
                break
            seen.add(key)
            idioms.append({
                'object': obj,
                'callees': callees,
                'site': site,
                'capture': f'{variable} = {capture.group(3).strip()}',
                'detail': (
                    f'{function_name} captures `{capture.group(3).strip()}` into '
                    f'`{variable}` and later checks whether it changed across the '
                    'intervening operations, taking corrective action on change'
                ),
            })
            break
    return idioms


def _macro_alias_backing_object(
    object_id: str,
    macro_defs: dict[str, dict[str, Any]] | None,
) -> str | None:
    """Resolve a macro:: alias object to its backing storage object when the
    macro body is available (e.g. macro::CUR_PTR -> ctxt->input::buffer)."""
    if not object_id.startswith('macro::') or not macro_defs:
        return None
    spec = macro_defs.get(object_id[len('macro::'):])
    if not spec:
        return None
    return _abstract_backing_object(spec.get('body') or '')


def _match_relocation_idiom(
    object_id: str,
    unresolved_callees: list[str],
    macro_defs: dict[str, dict[str, Any]] | None,
    relocation_idioms: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Upgrade an UNKNOWN effect when a codebase defensive idiom covers it.

    Both sides must agree on the backing object, and at least one unresolved
    callee (macro-expanded) must appear inside the idiom's guarded window.
    """
    if not relocation_idioms:
        return None
    resolved_object = object_id
    if object_id.startswith('macro::'):
        resolved_object = _macro_alias_backing_object(object_id, macro_defs) or object_id
    statement_callees: set[str] = set()
    for name in unresolved_callees or []:
        statement_callees.add(name)
        spec = (macro_defs or {}).get(name)
        if spec:
            for callee, _args in _extract_calls(spec.get('body') or ''):
                statement_callees.add(callee)
    for idiom in relocation_idioms:
        if idiom.get('object') != resolved_object:
            continue
        if statement_callees & set(idiom.get('callees') or []):
            return idiom
    return None


def _match_relocation_object(
    object_id: str,
    macro_defs: dict[str, dict[str, Any]] | None,
    relocation_idioms: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Object-level match: the codebase proves this backing object is
    relocation-prone, regardless of whether the current operation appears in
    the defensive window (defensive-pattern inconsistency evidence)."""
    if not relocation_idioms:
        return None
    resolved_object = object_id
    if object_id.startswith('macro::'):
        resolved_object = _macro_alias_backing_object(object_id, macro_defs) or object_id
    for idiom in relocation_idioms:
        if idiom.get('object') == resolved_object:
            return idiom
    return None


def _normalize_guard_atom(value: str) -> str:
    text = re.sub(r'\s+', '', str(value or '')).lower()
    text = re.sub(r'^(if|while|for)\(', '(', text)
    while len(text) >= 2 and text[0] == '(' and text[-1] == ')':
        text = text[1:-1]
    return text


def _branch_signature(controls: Any) -> tuple[str, ...]:
    return tuple(sorted({_normalize_guard_atom(item) for item in (controls or []) if _normalize_guard_atom(item)}))


def _guards_clearly_contradict(left: str, right: str) -> bool:
    left = _normalize_guard_atom(left)
    right = _normalize_guard_atom(right)
    if not left or not right:
        return False
    if left == f'!{right}' or right == f'!{left}':
        return True
    if left.startswith('!(') and left.endswith(')') and left[2:-1] == right:
        return True
    if right.startswith('!(') and right.endswith(')') and right[2:-1] == left:
        return True
    comparison = re.compile(r'^([a-z_]\w*)(==|!=)([^=]+)$')
    lm = comparison.match(left)
    rm = comparison.match(right)
    if lm and rm and lm.group(1) == rm.group(1) and lm.group(3) == rm.group(3):
        return {lm.group(2), rm.group(2)} == {'==', '!='}
    if lm and rm and lm.group(1) == rm.group(1) and lm.group(2) == rm.group(2) == '==' and lm.group(3) != rm.group(3):
        return True
    return False


def _controls_may_coexecute(left: Any, right: Any) -> bool:
    # Conservative: reject only direct, syntactically evident contradictions.
    for left_guard in left or []:
        for right_guard in right or []:
            if _guards_clearly_contradict(str(left_guard), str(right_guard)):
                return False
    return True


def _split_call_arguments(arguments: str) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = False
    quote = ''
    escaped = False
    for char in arguments:
        if in_string:
            current.append(char)
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                in_string = False
            continue
        if char in {'"', "'"}:
            in_string = True
            quote = char
            current.append(char)
        elif char in '([{':
            depth += 1
            current.append(char)
        elif char in ')]}':
            depth = max(0, depth - 1)
            current.append(char)
        elif char == ',' and depth == 0:
            result.append(''.join(current).strip())
            current = []
        else:
            current.append(char)
    if current or arguments.strip():
        result.append(''.join(current).strip())
    return result


def _extract_calls(code: str) -> list[tuple[str, list[str]]]:
    calls: list[tuple[str, list[str]]] = []
    blocked = {'if', 'for', 'while', 'switch', 'sizeof', 'return'}
    for match in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', code or ''):
        name = match.group(1)
        if name in blocked:
            continue
        start = match.end()
        depth = 1
        index = start
        in_string = False
        quote = ''
        escaped = False
        while index < len(code) and depth:
            char = code[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == quote:
                    in_string = False
            elif char in {'"', "'"}:
                in_string = True
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            index += 1
        if depth == 0:
            calls.append((name, _split_call_arguments(code[start:index - 1])))
    return calls


def _parameter_infos(function_code: str, language: str = 'c') -> list[dict[str, Any]]:
    try:
        tree = _function_tree_cached(function_code, language)
    except Exception:
        return []
    result: list[dict[str, Any]] = []
    for index in range(0, 256):
        info = get_parameter_info(tree.root_node, index)
        if not info:
            break
        result.append({**info, 'index': index})
    return result


def summarize_lifecycle_effects(
    function_code: str,
    function_name: str = '',
    language: str = 'c',
    callee_effects: dict[str, dict[str, Any]] | None = None,
    macro_defs: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a small reusable lifecycle-effect summary for call-site instantiation."""
    parameters = _parameter_infos(function_code, language)
    callee_effects = callee_effects or {}
    name_to_index = {item['name']: item['index'] for item in parameters if item.get('name')}
    summary: dict[str, Any] = {
        'function': function_name,
        'release_args': set(),
        'release_arg_fields': set(),
        'invalidate_args': set(),
        'return_alias_args': set(),
        'store_alias_args': set(),
        'ownership_transfer_args': set(),
    }
    try:
        records = _lifecycle_statements(function_code, language)
    except Exception:
        records = []
    transfer_name = re.compile(r'(?:take|adopt|steal|consume|own|transfer)', flags=re.I)
    field_path_re = re.compile(r'^([A-Za-z_]\w*)((?:(?:->|\.)[A-Za-z_]\w*)+)$')

    def _record_release_field(target: str) -> None:
        match = field_path_re.match(target or '')
        if match and match.group(1) in name_to_index:
            summary['release_arg_fields'].add(
                (name_to_index[match.group(1)], match.group(2))
            )

    for record in records:
        code = record.get('code', '')
        analysis_code = (
            expand_macro_statement(code, macro_defs) if macro_defs else code
        )
        release = _release_event(analysis_code)
        if release and release[1] in name_to_index:
            summary['release_args'].add(name_to_index[release[1]])
        elif release:
            _record_release_field(release[1])
        growth = _growth_event(analysis_code)
        if growth:
            # A resize statement may mention allocator/context handles alongside the
            # object whose storage changes. Propagating invalidation to every formal
            # parameter in that statement creates false lifecycle chains. Record only
            # a formal explicitly replaced by the assignment or passed as the storage
            # argument to a known realloc primitive.
            assignment = _simple_assignment(code)
            if assignment and assignment[0] in name_to_index:
                summary['invalidate_args'].add(name_to_index[assignment[0]])

            known_realloc = re.compile(
                r'^(?:realloc|xmlRealloc|g_realloc|krealloc|OPENSSL_realloc)$',
                flags=re.I,
            )
            for callee, args in _extract_calls(analysis_code):
                if not known_realloc.match(callee) or not args:
                    continue
                variable = _normalize_lvalue(args[0])
                if variable in name_to_index:
                    summary['invalidate_args'].add(name_to_index[variable])
        return_match = re.search(r'\breturn\b\s*([A-Za-z_]\w*)', code)
        if return_match and return_match.group(1) in name_to_index:
            summary['return_alias_args'].add(name_to_index[return_match.group(1)])
        assignment = _simple_assignment(code)
        if assignment:
            lhs, rhs = assignment
            for name, index in name_to_index.items():
                if re.search(rf'\b{re.escape(name)}\b', rhs) and ('->' in lhs or '.' in lhs):
                    summary['store_alias_args'].add(index)
        for callee, args in _extract_calls(analysis_code):
            if transfer_name.search(callee):
                for arg_index, argument in enumerate(args):
                    variable = _normalize_lvalue(argument)
                    if variable in name_to_index:
                        summary['ownership_transfer_args'].add(name_to_index[variable])
            child_summary = callee_effects.get(callee) or {}
            for child_item in child_summary.get('release_arg_fields', []) or []:
                # Compose field-path releases transitively: child releases
                # arg_ci->path; map the concrete argument back onto our formals.
                try:
                    child_index, child_path = int(child_item[0]), str(child_item[1])
                except (TypeError, ValueError, IndexError):
                    continue
                if not (0 <= child_index < len(args)):
                    continue
                variable = _normalize_lvalue(args[child_index])
                if variable in name_to_index:
                    summary['release_arg_fields'].add(
                        (name_to_index[variable], child_path)
                    )
                    continue
                field_match = field_path_re.match(variable)
                if field_match and field_match.group(1) in name_to_index:
                    summary['release_arg_fields'].add(
                        (name_to_index[field_match.group(1)],
                         field_match.group(2) + child_path)
                    )
            field_map = {
                'release_args': 'release_args',
                'invalidate_args': 'invalidate_args',
                'return_alias_args': 'return_alias_args',
                'store_alias_args': 'store_alias_args',
                'ownership_transfer_args': 'ownership_transfer_args',
            }
            for child_field, current_field in field_map.items():
                for child_index in child_summary.get(child_field, []) or []:
                    child_index = _safe_int(child_index, -1)
                    if 0 <= child_index < len(args):
                        variable = _normalize_lvalue(args[child_index])
                        if variable in name_to_index:
                            summary[current_field].add(name_to_index[variable])
    return {
        key: sorted(value) if isinstance(value, set) else value
        for key, value in summary.items()
    }


def analyze_lifecycle_paths_by_param_index(
    function_code: str,
    param_index: int,
    function_name: str = '',
    language: str = 'c',
    abstract_object_hint: str | None = None,
    callee_effects: dict[str, dict[str, Any]] | None = None,
    macro_defs: dict[str, dict[str, Any]] | None = None,
    caller_names: list[str] | None = None,
    externally_invoked: bool = False,
    relocation_idioms: list[dict[str, Any]] | None = None,
    caller_serialized: bool = False,
) -> list[dict[str, Any]]:
    parameters = _parameter_infos(function_code, language)
    if param_index < 0 or param_index >= len(parameters):
        return []
    variable = parameters[param_index].get('name')
    if not variable or variable.startswith('[unnamed_param_'):
        return []
    object_overrides = {
        variable: abstract_object_hint or f'parameter::{function_name or "[unknown]"}::{param_index}::{variable}'
    }
    return analyze_lifecycle_paths(
        function_code,
        function_name=function_name,
        language=language,
        seed_variables=[variable],
        object_overrides=object_overrides,
        callee_effects=callee_effects,
        macro_defs=macro_defs,
        caller_names=caller_names,
        externally_invoked=externally_invoked,
        relocation_idioms=relocation_idioms,
        caller_serialized=caller_serialized,
    )


def analyze_lifecycle_paths(
    function_code: str,
    function_name: str = '',
    language: str = 'c',
    max_candidates: int | None = None,
    seed_variables: list[str] | None = None,
    object_overrides: dict[str, str] | None = None,
    callee_effects: dict[str, dict[str, Any]] | None = None,
    macro_defs: dict[str, dict[str, Any]] | None = None,
    caller_names: list[str] | None = None,
    externally_invoked: bool = False,
    relocation_idioms: list[dict[str, Any]] | None = None,
    caller_serialized: bool = False,
) -> list[dict[str, Any]]:
    """Generate ordered, same-object UAF/double-free candidates.

    This pass is additive. It does not suppress ordinary data-flow paths. Candidate
    construction is object-centric and records event sites, branch signatures and
    refresh boundaries so the verifier receives concrete lifecycle evidence.
    """
    try:
        records = _lifecycle_statements(function_code, language)
    except Exception as exc:
        print(f"[Lifecycle] parse failed in {function_name or '[unknown]'}: {exc}")
        return []

    object_overrides = object_overrides or {}
    callee_effects = callee_effects or {}
    aliases: dict[str, str] = {}
    capture_code: dict[str, str] = {}
    null_variables: set[str] = set()
    invalidations: list[dict[str, Any]] = []
    releases: dict[str, list[dict[str, Any]]] = {}
    ownership_events: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    # Observation-level evidence (P0/P2): an opaque call or macro statement whose
    # effect on an aliased object is unknown, followed by an un-refreshed use, or
    # overlapping a provable helper release. These are anchors for the LLM stages,
    # not completed patterns. Suspects are collected unbounded during the scan and
    # ranked/truncated afterwards: source order must not decide which survive.
    at_risk: dict[str, dict[str, Any]] = {}
    # F3a: field-path handles passed to opaque (possibly indirect) calls —
    # `io_data->kiocb->ki_complete(io_data->kiocb, ...)` may release the object;
    # a later deref of the same path anchors a stale-handle observation.
    field_handle_risk: dict[str, dict[str, Any]] = {}
    # F3b: `ReleaseNamed(&x)` idiom — the callee may release the object and can
    # only clear the passed handle; other aliases of the object stay dangling.
    # The release-ish name is used ONLY to raise this heuristic anchor, never
    # as proof of an effect.
    addr_release_risk: dict[str, dict[str, Any]] = {}
    opaque_calls_seen: list[dict[str, Any]] = []
    suspect_candidates: list[dict[str, Any]] = []
    # Container-growth sibling tracking: `grow_clean(s->init_buf, ...)` may move
    # the container's backing storage; sibling pointer fields (s->init_msg) whose
    # alias into that storage was established inside a callee are invisible to the
    # in-file alias map, so they are tracked heuristically per container.
    grown_containers: list[dict[str, Any]] = []
    assigned_lvalues: set[str] = set()
    for _record in records:
        _assignment = _simple_assignment(_record.get('code', ''))
        if _assignment:
            assigned_lvalues.add(_assignment[0])

    for variable in seed_variables or []:
        aliases[variable] = object_overrides.get(
            variable,
            f'parameter::{function_name or "[unknown]"}::{variable}',
        )
        capture_code[variable] = f'Function parameter `{variable}` enters {function_name or "[unknown]"}'

    def make_event(kind: str, record: dict[str, Any], variable: str, object_id: str, **extra: Any) -> dict[str, Any]:
        start_byte = _safe_int(record.get('start_byte'), -1)
        payload = {
            'event_kind': kind,
            'code': record.get('code', ''),
            'controls': list(record.get('controls') or []),
            'branch_signature': list(record.get('branch_signature') or ()),
            'statement_index': _safe_int(record.get('statement_index'), -1),
            'start_byte': start_byte,
            'variable': variable,
            'alias_id': variable,
            'abstract_object': object_id,
            'object_id': object_id,
        }
        payload.update(extra)
        payload['event_id'] = f"{kind}:{function_name or '[unknown]'}:{start_byte}:{variable}:{object_id}"
        return payload

    def active_aliases(object_id: str) -> list[str]:
        return [name for name, obj in aliases.items() if obj == object_id]

    def add_invalidation(event: dict[str, Any], object_id: str, skip_variables: set[str] | None = None) -> None:
        skip_variables = skip_variables or set()
        names = active_aliases(object_id) or [str(event.get('variable') or '')]
        for alias in names:
            if not alias or alias in skip_variables:
                continue
            invalidations.append({**event, 'variable': alias, 'alias_id': alias})

    for index, record in enumerate(records):
        record = dict(record)
        record['statement_index'] = index
        code = record['code']
        # Macro-expanded text is used ONLY for event recognition (release/growth/
        # call extraction/invalidation targets). Assignment detection and display
        # always use the original statement text.
        analysis_code = (
            expand_macro_statement(code, macro_defs) if macro_defs else code
        )
        assignment = _simple_assignment(code)
        pre_aliases = dict(aliases)
        release = _release_event(analysis_code)
        growth = _growth_event(analysis_code)
        event_generated_here: list[dict[str, Any]] = []

        # Direct release/free/delete and wrapper releases are instantiated as the same
        # object event. free(NULL) is a blocker, not a double-free candidate.
        release_requests: list[tuple[str, str, str]] = []
        if release:
            release_requests.append((release[0], release[1], 'direct'))
        for callee, args in _extract_calls(analysis_code):
            summary = callee_effects.get(callee) or {}
            for arg_index in summary.get('release_args', []) or []:
                if 0 <= _safe_int(arg_index, -1) < len(args):
                    release_requests.append((f'{callee}:release_arg{arg_index}', _normalize_lvalue(args[arg_index]), 'summary'))
            for field_item in summary.get('release_arg_fields', []) or []:
                # Field-path release via helper summary: kfree(arg->rq->cmd)
                # inside the callee instantiates as a release of the concrete
                # caller-side field path.
                try:
                    field_index, field_path = int(field_item[0]), str(field_item[1])
                except (TypeError, ValueError, IndexError):
                    continue
                if 0 <= field_index < len(args):
                    concrete = f"{_normalize_lvalue(args[field_index])}{field_path}"
                    release_requests.append((
                        f'{callee}:release_arg{field_index}{field_path}',
                        concrete,
                        'summary',
                    ))

        seen_release_requests: set[tuple[str, str]] = set()
        for release_kind, variable, source_kind in release_requests:
            marker = (release_kind, variable)
            if marker in seen_release_requests or not variable:
                continue
            seen_release_requests.add(marker)
            if variable in null_variables:
                continue
            object_id = pre_aliases.get(variable, object_overrides.get(variable, f'variable::{variable}'))
            event = make_event(
                'RELEASE', record, variable, object_id,
                invalidation_kind=release_kind,
                effect_source=source_kind,
            )
            previous_releases = releases.setdefault(object_id, [])
            compatible_previous = next(
                (
                    previous for previous in reversed(previous_releases)
                    if _controls_may_coexecute(previous.get('controls'), event.get('controls'))
                ),
                None,
            )
            if compatible_previous is not None:
                candidates.append({
                    'kind': 'double_free',
                    'variable': variable,
                    'object': object_id,
                    'events': [
                        {
                            'event_kind': 'OBJECT_REFERENCE',
                            'code': capture_code.get(variable, f'Object `{variable}` references {object_id}'),
                            'controls': [],
                            'branch_signature': [],
                            'statement_index': max(0, _safe_int(compatible_previous.get('statement_index'), 0) - 1),
                            'start_byte': _safe_int(compatible_previous.get('start_byte'), -1),
                            'variable': variable,
                            'alias_id': variable,
                            'abstract_object': object_id,
                            'object_id': object_id,
                            'event_id': f'OBJECT_REFERENCE:{function_name}:{object_id}',
                        },
                        compatible_previous,
                        {**event, 'event_kind': 'RELEASE_AGAIN'},
                    ],
                })
            previous_releases.append(event)
            add_invalidation(event, object_id)
            event_generated_here.append(event)

            # Observation: a provable helper release whose concrete field path
            # extends an earlier opaque call's argument (e.g. opaque
            # `blk_end_request_all(srp->rq, ...)` followed by a helper that
            # provably kfree()s `srp->rq->cmd`). The opaque call may already
            # have released the same object; emitted as an anchor, not a verdict.
            if (
                _STALE_POINTER_OBS_ENABLED
                and source_kind == 'summary'
                and ('->' in variable or '.' in variable)
            ):
                # Pair with the nearest preceding opaque call and prefer the
                # longest matching argument prefix.
                for opaque in sorted(
                    opaque_calls_seen,
                    key=lambda item: _safe_int(item.get('statement_index'), -1),
                    reverse=True,
                ):
                    if _safe_int(opaque.get('statement_index'), -1) >= index:
                        continue
                    if not _controls_may_coexecute(opaque.get('controls'), record.get('controls')):
                        continue
                    matches = [
                        norm for norm in (opaque.get('args') or [])
                        if variable == norm
                        or variable.startswith(norm + '->')
                        or variable.startswith(norm + '.')
                    ]
                    if not matches:
                        continue
                    overlap = max(matches, key=len)
                    unknown_event = make_event(
                        'UNKNOWN_EFFECT', opaque['record'], variable, object_id,
                        effect_source=(
                            f'opaque call argument `{overlap}` is a prefix of the '
                            f'provably released `{variable}`; the earlier call may '
                            'already have released the same object'
                        ),
                        heuristic=True,
                        evidence_status='unknown_effect',
                    )
                    # Deterministic event order, stated so neither LLM stage has to
                    # reconstruct it from byte offsets: the opaque call precedes this
                    # proven release on a syntactically branch-compatible path.
                    event['ordering_note'] = (
                        f"analyzer ordering: the opaque operation `{opaque['record'].get('code', '')}` "
                        f"precedes this proven release of `{variable}` on a syntactically "
                        'branch-compatible path; a double-free requires that earlier call '
                        'to have released the same object'
                    )
                    suspect_candidates.append({
                        'kind': 'release_overlap_suspect',
                        'variable': variable,
                        'object': object_id,
                        'evidence_status': 'observation',
                        # The release side is summary-proven; the unknown side is
                        # the earlier opaque call. A release is a strong terminal.
                        'effect_strength': 'summary_proven',
                        'use_strength': 'strong',
                        'events': [unknown_event, event],
                    })
                    break

        # Growth/reallocation can move backing storage. For `p = realloc(p, ...)`, p
        # is refreshed by the assignment while pre-existing aliases remain stale.
        invalidate_requests: list[tuple[str, str, str]] = []
        if growth:
            realloc_match = re.search(r'\brealloc\s*\(\s*([A-Za-z_]\w*)', analysis_code, flags=re.I)
            if realloc_match:
                invalidate_requests.append((growth, realloc_match.group(1), 'direct'))
            else:
                for variable, object_id in pre_aliases.items():
                    if '::buffer' in object_id or '::storage' in object_id:
                        if re.search(rf'\b{re.escape(variable)}\b', analysis_code) or object_id.split('::', 1)[0] in analysis_code:
                            invalidate_requests.append((growth, variable, 'direct'))
        for callee, args in _extract_calls(analysis_code):
            summary = callee_effects.get(callee) or {}
            for arg_index in summary.get('invalidate_args', []) or []:
                if 0 <= _safe_int(arg_index, -1) < len(args):
                    invalidate_requests.append((f'{callee}:invalidate_arg{arg_index}', _normalize_lvalue(args[arg_index]), 'summary'))

        seen_invalidations: set[tuple[str, str]] = set()
        if growth and _SIBLING_UAF_INFERENCE:
            member_arg = re.search(
                r'\(\s*&?\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+)\s*[,\)]',
                analysis_code,
            )
            if member_arg:
                member_path = re.sub(r'\s+', '', member_arg.group(1))
                parts = re.split(r'->|\.', member_path)
                buffer_member = parts[-1]
                container = parts[0] if len(parts) == 2 else member_path[:member_path.rfind(buffer_member)].rstrip('-.>')
                if container and container != buffer_member and not any(
                    item['container'] == container for item in grown_containers
                ):
                    grown_containers.append({
                        'container': container,
                        'buffer_member': buffer_member,
                        'event': make_event(
                            'INVALIDATE', record, member_path, f'{member_path}::buffer',
                            invalidation_kind=growth,
                            effect_source='container_growth',
                        ),
                        'statement_index': index,
                        'controls': list(record.get('controls') or []),
                        'refreshed': set(),
                        'reported': set(),
                    })
        assignment_lhs = assignment[0] if assignment else None
        for invalidation_kind, variable, source_kind in invalidate_requests:
            marker = (invalidation_kind, variable)
            if marker in seen_invalidations or not variable:
                continue
            seen_invalidations.add(marker)
            object_id = pre_aliases.get(variable, object_overrides.get(variable, f'variable::{variable}'))
            event = make_event(
                'INVALIDATE', record, variable, object_id,
                invalidation_kind=invalidation_kind,
                effect_source=source_kind,
            )
            skip = {assignment_lhs} if assignment_lhs and assignment_lhs == variable else set()
            add_invalidation(event, object_id, skip_variables=skip)
            event_generated_here.append(event)

        # Ownership-transfer/store effects are preserved as evidence for the verifier;
        # they do not suppress a candidate by themselves because wrapper semantics may
        # be incomplete.
        transfer_events: list[dict[str, Any]] = []
        for callee, args in _extract_calls(code):
            summary = callee_effects.get(callee) or {}
            effect_indices = set(summary.get('ownership_transfer_args', []) or []) | set(summary.get('store_alias_args', []) or [])
            for arg_index in effect_indices:
                if 0 <= _safe_int(arg_index, -1) < len(args):
                    variable = _normalize_lvalue(args[arg_index])
                    if not variable:
                        continue
                    object_id = pre_aliases.get(variable, f'variable::{variable}')
                    transfer_event = make_event(
                        'OWNERSHIP_TRANSFER', record, variable, object_id,
                        effect_source=f'{callee}:arg{arg_index}',
                    )
                    transfer_events.append(transfer_event)
                    ownership_events.append(transfer_event)

        # Apply the assignment after invalidation detection so stale aliases survive a
        # realloc while the assigned pointer receives a fresh object generation.
        if assignment:
            lhs, rhs = assignment
            is_null = bool(re.fullmatch(r'(?:NULL|nullptr|0|\(void\s*\*\)\s*0)', rhs.strip()))
            # A refresh clears at-risk observations only when the assignment is no
            # more guarded than the at-risk statement; a conditional refresh inside
            # a side branch must not clear an at-risk raised on the main path.
            def _clears_at_risk(var: str) -> None:
                entry = at_risk.get(var)
                if entry is None:
                    return
                risk_controls = {
                    _normalize_guard_atom(item)
                    for item in (entry.get('controls') or [])
                    if _normalize_guard_atom(item)
                }
                refresh_controls = {
                    _normalize_guard_atom(item)
                    for item in (record.get('controls') or [])
                    if _normalize_guard_atom(item)
                }
                if refresh_controls <= risk_controls:
                    at_risk.pop(var, None)

            if is_null:
                aliases.pop(lhs, None)
                capture_code.pop(lhs, None)
                null_variables.add(lhs)
                invalidations = [item for item in invalidations if item.get('variable') != lhs]
                at_risk.pop(lhs, None)
            else:
                null_variables.discard(lhs)
                object_id = _abstract_backing_object(rhs)
                alias_match = re.fullmatch(r'[&*()\s]*([A-Za-z_]\w*)', rhs)
                allocation_match = re.search(r'\b(malloc|calloc|strdup|xmlMalloc|kmalloc|new|realloc)\b', rhs)
                if object_id:
                    aliases[lhs] = object_id
                    capture_code[lhs] = code
                    invalidations = [item for item in invalidations if item.get('variable') != lhs]
                    _clears_at_risk(lhs)
                elif alias_match:
                    rhs_var = alias_match.group(1)
                    if re.fullmatch(r'[A-Z][A-Z0-9_]{2,}', rhs_var):
                        # Pointer copied from an all-caps macro value (e.g.
                        # `q = CUR_PTR`): the macro body is unavailable, so the
                        # object is opaque but still alias-tracked for
                        # stale-pointer observations.
                        object_id = f'macro::{rhs_var}'
                        aliases[lhs] = object_id
                        capture_code[lhs] = code
                        invalidations = [item for item in invalidations if item.get('variable') != lhs]
                        _clears_at_risk(lhs)
                    else:
                        object_id = pre_aliases.get(rhs_var, aliases.get(rhs_var, f'variable::{rhs_var}'))
                        aliases.setdefault(rhs_var, object_id)
                        capture_code.setdefault(rhs_var, f'Pointer/object referenced by `{rhs_var}`')
                        aliases[lhs] = object_id
                        capture_code[lhs] = code
                        # If rhs is already stale, lhs becomes another stale alias.
                        stale_rhs = [item for item in invalidations if item.get('variable') == rhs_var]
                        invalidations = [item for item in invalidations if item.get('variable') != lhs]
                        invalidations.extend({**item, 'variable': lhs, 'alias_id': lhs} for item in stale_rhs)
                        if rhs_var in at_risk:
                            at_risk[lhs] = {**at_risk[rhs_var], 'variable': lhs, 'alias_id': lhs}
                            _clears_at_risk(lhs)
                        else:
                            _clears_at_risk(lhs)
                elif allocation_match:
                    aliases[lhs] = f'allocation::{function_name or "[unknown]"}::{lhs}@{_safe_int(record.get("start_byte"), -1)}'
                    capture_code[lhs] = code
                    invalidations = [item for item in invalidations if item.get('variable') != lhs]
                    _clears_at_risk(lhs)
                elif lhs in aliases:
                    aliases.pop(lhs, None)
                    capture_code.pop(lhs, None)
                    invalidations = [item for item in invalidations if item.get('variable') != lhs]
                    at_risk.pop(lhs, None)

        # Search for stale uses after the event and after assignment-refresh handling.
        for invalidation in list(invalidations):
            variable = str(invalidation.get('variable') or '')
            if not variable or index <= _safe_int(invalidation.get('statement_index'), -1):
                continue
            if not re.search(rf'\b{re.escape(variable)}\b', code):
                continue
            if release and release[1] == variable:
                continue
            if assignment and assignment[0] == variable:
                continue
            if not _controls_may_coexecute(invalidation.get('controls'), record.get('controls')):
                continue
            if not _pointer_consuming_use(code, variable):
                continue
            object_id = str(invalidation.get('object_id') or invalidation.get('abstract_object') or f'variable::{variable}')
            use_event = make_event('USE', record, variable, object_id)
            intervening_ownership = [
                event for event in ownership_events
                if event.get('object_id') == object_id
                and _safe_int(invalidation.get('statement_index'), -1)
                    < _safe_int(event.get('statement_index'), -1) < index
            ]
            candidates.append({
                'kind': 'use_after_free',
                'variable': variable,
                'object': object_id,
                'events': [
                    {
                        'event_kind': 'ALIAS_CAPTURE',
                        'code': capture_code.get(variable, f'Pointer `{variable}` references {object_id}'),
                        'controls': [],
                        'branch_signature': [],
                        'statement_index': max(0, _safe_int(invalidation.get('statement_index'), 0) - 1),
                        'start_byte': _safe_int(invalidation.get('start_byte'), -1),
                        'variable': variable,
                        'alias_id': variable,
                        'abstract_object': object_id,
                        'object_id': object_id,
                        'event_id': f'ALIAS_CAPTURE:{function_name}:{object_id}:{variable}',
                    },
                    invalidation,
                    *intervening_ownership,
                    use_event,
                ],
            })

        # Sibling-field stale uses of grown containers. A growth call on
        # `container->buffer_member` may move the backing storage; a sibling
        # pointer field (never assigned in this function, so its pointee was
        # established elsewhere) used afterwards may reference the old storage.
        # Heuristic candidate: the verifier decides with the explicit note.
        storage_fields = {'data', 'buf', 'buffer', 'cur', 'base', 'end', 'storage', 'content'}
        for grown in grown_containers:
            if index <= _safe_int(grown.get('statement_index'), -1):
                continue
            if not _controls_may_coexecute(grown.get('controls'), record.get('controls')):
                continue
            container = grown['container']
            for member_match in re.finditer(
                rf'\b{re.escape(container)}\s*(->|\.)\s*([A-Za-z_]\w*)', code
            ):
                field = member_match.group(2)
                if field == grown['buffer_member'] or field in storage_fields:
                    continue
                sibling = f"{container}{member_match.group(1)}{field}"
                if sibling in grown['reported'] or sibling in grown['refreshed']:
                    continue
                if sibling in assigned_lvalues:
                    continue
                if assignment and assignment[0] == sibling and container in assignment[1]:
                    grown['refreshed'].add(sibling)
                    continue
                if not _pointer_consuming_use(code, sibling):
                    continue
                grown['reported'].add(sibling)
                use_event = make_event(
                    'USE', record, sibling, f"{container}->{grown['buffer_member']}::buffer",
                )
                use_event['effect_source'] = (
                    f"sibling inference: {sibling} is never assigned in this function; "
                    f"it may reference the backing storage moved by the growth call"
                )
                # The alias relation below is inferred, not established in-file;
                # the verifier must treat it as an alias hypothesis, not a fact.
                use_event['heuristic'] = True
                use_event['evidence_status'] = 'inferred_alias'
                grown['event']['heuristic'] = True
                candidates.append({
                    'kind': 'use_after_free',
                    'variable': sibling,
                    'object': f"{container}->{grown['buffer_member']}::buffer",
                    'events': [grown['event'], use_event],
                })

        # --- Observation-level lifecycle evidence (stale-pointer suspects) ------
        # Statements with a real release/growth event are handled by the completed
        # candidate machinery above; this block only covers opaque operations.
        if _STALE_POINTER_OBS_ENABLED and not release and not growth:
            # Derive the statement's lifecycle effect first: only statements whose
            # effect stays UNKNOWN after macro expansion + in-file summaries may
            # raise an observation. A statement whose every call resolves to an
            # effect-free in-file summary (or whose macro body expands to plain
            # assignments) is PROVEN_NO_EFFECT and must not anchor a suspect.
            effect = _derive_statement_effect(analysis_code, callee_effects)
            unresolved = set(effect.get('unresolved') or [])
            statement_opaque_args: list[str] = []
            for callee, args in _extract_calls(analysis_code):
                summary = callee_effects.get(callee) or {}
                if any(
                    summary.get(key)
                    for key in ('release_args', 'release_arg_fields', 'invalidate_args')
                ):
                    continue  # callee effects are (partially) known
                if callee not in unresolved:
                    continue  # pure callee or in-file callee with an effect-free summary
                for argument in args:
                    normalized = _normalize_lvalue(argument)
                    if normalized and not re.fullmatch(r'[-+]?\d+|NULL|nullptr', normalized):
                        statement_opaque_args.append(normalized)
            bare_macro_match = re.fullmatch(r'\s*([A-Z][A-Z0-9_]{2,})\s*;?', code)
            bare_macro = bool(bare_macro_match)
            if bare_macro:
                macro_name = bare_macro_match.group(1)
                if macro_defs and macro_name in macro_defs:
                    if effect.get('effect_kind') == 'PROVEN_NO_EFFECT':
                        # The macro body is fully visible (e.g. pointer arithmetic
                        # only): it cannot release or move the tracked storage.
                        bare_macro = False
                else:
                    # Definition unavailable: the bare macro itself is the opaque
                    # operation — never call this PROVEN_NO_EFFECT just because the
                    # unexpanded text contains no call.
                    effect = {
                        'effect_kind': 'UNKNOWN',
                        'provenance': 'unresolved',
                        'unresolved': [macro_name],
                    }
            if statement_opaque_args or bare_macro:
                unresolved_text = ''
                if effect.get('unresolved'):
                    unresolved_text = (
                        '; unresolved callee(s) keeping the effect unknown: '
                        + ', '.join(effect['unresolved'])
                    )
                opaque_calls_seen.append({
                    'statement_index': index,
                    'controls': list(record.get('controls') or []),
                    'record': dict(record),
                    'args': statement_opaque_args,
                    'bare_macro': bare_macro,
                })
                # (i) buffer/storage alias + opaque call whose argument is the
                #     object base (prefix): the call may release/move the storage.
                # (ii) macro-sourced alias + bare all-caps macro statement.
                for variable, object_id in list(aliases.items()):
                    if variable in at_risk:
                        continue
                    is_macro_obj = object_id.startswith('macro::')
                    is_buffer_obj = '::buffer' in object_id or '::storage' in object_id
                    if not (is_macro_obj or is_buffer_obj):
                        continue
                    base = object_id.split('::', 1)[0]
                    hit = False
                    effect_strength = 'ancestor_or_macro'
                    if is_buffer_obj:
                        if any(base == norm for norm in statement_opaque_args):
                            # The opaque call received the object's own handle.
                            hit = True
                            effect_strength = 'exact_owner'
                        else:
                            hit = any(
                                base.startswith(norm + '->')
                                or base.startswith(norm + '.')
                                for norm in statement_opaque_args
                            )
                    if not hit and bare_macro and is_macro_obj:
                        hit = True
                    if not hit:
                        continue
                    event_effect_kind = effect.get('effect_kind')
                    event_effect_source = (
                        'opaque call/macro with unknown effect on the object; '
                        'it may release, move, or reallocate the backing storage'
                        + unresolved_text
                    )
                    if event_effect_kind == 'UNKNOWN':
                        idiom = _match_relocation_idiom(
                            object_id,
                            effect.get('unresolved') or [],
                            macro_defs,
                            relocation_idioms,
                        )
                        if idiom is not None:
                            event_effect_kind = 'MAY_RELOCATE'
                            event_effect_source = (
                                f'codebase defensive idiom at {idiom["site"]}: '
                                f'{idiom["detail"]} — the codebase treats this '
                                'operation family as potentially relocating the '
                                'backing storage (file-local behavioral evidence, '
                                'not a name-based guess)'
                                + unresolved_text
                            )
                        else:
                            pattern = _match_relocation_object(
                                object_id, macro_defs, relocation_idioms,
                            )
                            if pattern is not None:
                                event_effect_kind = 'MAY_RELOCATE'
                                event_effect_source = (
                                    f'no defensive window covers this operation '
                                    f'directly, but a codebase defensive idiom at '
                                    f'{pattern["site"]} proves the backing storage '
                                    f'is relocation-prone ({pattern["detail"]}); '
                                    'this chain holds a raw pointer into that '
                                    'storage across the operation with no '
                                    'relocation defense of its own — '
                                    'defensive-pattern inconsistency; the '
                                    'relocation link is inferred from the '
                                    "codebase's own defensive pattern, weaker "
                                    'than direct window coverage'
                                    + unresolved_text
                                )
                    risk_event = make_event(
                        'UNKNOWN_EFFECT', record, variable, object_id,
                        effect_source=event_effect_source,
                        heuristic=True,
                        evidence_status='unknown_effect',
                        effect_strength=effect_strength,
                        effect_kind=event_effect_kind,
                        unresolved_callees=effect.get('unresolved') or [],
                    )
                    at_risk[variable] = risk_event
                # (iii) field-path handles (F3a): the opaque call received a field
                # path as argument (the object handle, e.g. `io_data->kiocb` into
                # an indirect callback); a later deref of the same path without
                # reassignment anchors a stale-handle observation.
                for normalized in statement_opaque_args:
                    if '->' not in normalized and '.' not in normalized:
                        continue
                    if normalized in field_handle_risk:
                        continue
                    field_handle_risk[normalized] = make_event(
                        'UNKNOWN_EFFECT', record, normalized, f'field_handle::{normalized}',
                        effect_source=(
                            f'opaque call received the object handle `{normalized}` '
                            '(possibly an indirect callback); it may release the '
                            'referenced object'
                            + unresolved_text
                        ),
                        heuristic=True,
                        evidence_status='unknown_effect',
                        effect_strength='exact_owner',
                        effect_kind=effect.get('effect_kind'),
                        unresolved_callees=effect.get('unresolved') or [],
                    )
                # (iv) release-named opaque callee with an address-of argument
                # (F3b): `DeleteImageFromList(&tmp)` may release the object and can
                # clear only the passed handle; other aliases stay dangling. The
                # name is only a raising heuristic, never effect proof.
                for callee, args in _extract_calls(analysis_code):
                    if callee not in unresolved:
                        continue
                    if not _RELEASE_HINT_CALLEE.search(callee):
                        continue
                    for argument in args:
                        addr = re.fullmatch(r'&\s*\*?\s*([A-Za-z_]\w*)', (argument or '').strip())
                        if not addr:
                            continue
                        handle = addr.group(1)
                        handle_object = aliases.get(handle)
                        if not handle_object or handle_object in addr_release_risk:
                            continue
                        addr_release_risk[handle_object] = make_event(
                            'UNKNOWN_EFFECT', record, handle, handle_object,
                            effect_source=(
                                f'opaque release-named call `{callee}(&{handle})` may '
                                'release the object and can clear only the passed '
                                'handle; other aliases of the same object stay dangling'
                            ),
                            heuristic=True,
                            evidence_status='unknown_effect',
                            effect_strength='exact_owner',
                            effect_kind=effect.get('effect_kind'),
                            unresolved_callees=effect.get('unresolved') or [],
                            object_aliases=sorted(
                                name for name, obj in aliases.items() if obj == handle_object
                            ),
                        )

        # Observation candidate: at-risk alias used later without an intervening
        # guaranteed refresh. This is an anchor for the LLM, not a verdict.
        if _STALE_POINTER_OBS_ENABLED and at_risk:
            for variable, risk_event in list(at_risk.items()):
                if _safe_int(risk_event.get('statement_index'), -1) >= index:
                    continue
                if not re.search(rf'\b{re.escape(variable)}\b', code):
                    continue
                if release and release[1] == variable:
                    continue
                if assignment and assignment[0] == variable:
                    continue
                if not _controls_may_coexecute(risk_event.get('controls'), record.get('controls')):
                    continue
                if not _pointer_consuming_use(code, variable):
                    continue
                object_id = str(risk_event.get('object_id') or f'variable::{variable}')
                already_completed = any(
                    candidate['kind'] == 'use_after_free'
                    and candidate['variable'] == variable
                    and any(
                        event.get('event_kind') == 'USE'
                        and _safe_int(event.get('start_byte'), -1) == _safe_int(record.get('start_byte'), -1)
                        for event in candidate['events']
                    )
                    for candidate in candidates
                )
                if already_completed:
                    at_risk.pop(variable, None)
                    continue
                use_event = make_event('USE', record, variable, object_id)
                use_event['evidence_status'] = 'observation'
                # Deterministic event order, stated so neither LLM stage has to
                # reconstruct it from byte offsets. By construction (refresh of the
                # alias clears the at-risk entry) no refresh the analyzer recognizes
                # intervenes between the opaque operation and this use.
                use_event['ordering_note'] = (
                    f'analyzer ordering: the most recent capture/refresh of `{variable}` '
                    f'({capture_code.get(variable, "not shown")}) precedes the opaque '
                    f'operation `{risk_event.get("code", "")}`; no refresh of '
                    f'`{variable}` recognized by the analyzer intervenes between that '
                    'opaque operation and this use'
                )
                suspect_candidates.append({
                    'kind': 'stale_pointer_suspect',
                    'variable': variable,
                    'object': object_id,
                    'evidence_status': 'observation',
                    'effect_strength': risk_event.get('effect_strength', 'ancestor_or_macro'),
                    'use_strength': _pointer_use_strength(code, variable),
                    'events': [
                        {
                            'event_kind': 'ALIAS_CAPTURE',
                            'code': capture_code.get(variable, f'Pointer `{variable}` references {object_id}'),
                            'controls': [],
                            'branch_signature': [],
                            'statement_index': max(0, _safe_int(risk_event.get('statement_index'), 0) - 1),
                            'start_byte': _safe_int(risk_event.get('start_byte'), -1),
                            'variable': variable,
                            'alias_id': variable,
                            'abstract_object': object_id,
                            'object_id': object_id,
                            'event_id': f'ALIAS_CAPTURE:{function_name}:{object_id}:{variable}',
                        },
                        risk_event,
                        use_event,
                    ],
                })
                at_risk.pop(variable, None)

        # Observation candidates (F3a): field-path handle dereferenced after an
        # opaque call received it, with no intervening reassignment of the path.
        if _STALE_POINTER_OBS_ENABLED and field_handle_risk:
            for field_path, risk_event in list(field_handle_risk.items()):
                if _safe_int(risk_event.get('statement_index'), -1) >= index:
                    continue
                if not _controls_may_coexecute(risk_event.get('controls'), record.get('controls')):
                    continue
                if assignment and assignment[0] == field_path:
                    field_handle_risk.pop(field_path, None)
                    continue
                # Require a strong use: a deref of the handle's pointee
                # (`io_data->kiocb->ki_flags`), not another call-arg pass.
                if not re.search(rf'(?<![\w>.]){re.escape(field_path)}\s*(?:->|\.)', code):
                    continue
                object_id = str(risk_event.get('object_id') or f'field_handle::{field_path}')
                use_event = make_event('USE', record, field_path, object_id)
                use_event['evidence_status'] = 'observation'
                use_event['ordering_note'] = (
                    f'analyzer ordering: the opaque call received `{field_path}` and no '
                    f'reassignment of `{field_path}` recognized by the analyzer intervenes '
                    'between that call and this dereference'
                )
                suspect_candidates.append({
                    'kind': 'stale_pointer_suspect',
                    'variable': field_path,
                    'object': object_id,
                    'evidence_status': 'observation',
                    'effect_strength': risk_event.get('effect_strength', 'exact_owner'),
                    'use_strength': 'strong',
                    'events': [risk_event, use_event],
                })
                field_handle_risk.pop(field_path, None)

        # Observation candidates (F3b): a different alias of the object used after
        # a release-named `&handle` call; the callee can only clear the passed
        # handle, so this alias stays dangling.
        if _STALE_POINTER_OBS_ENABLED and addr_release_risk:
            for object_id, risk_event in list(addr_release_risk.items()):
                if _safe_int(risk_event.get('statement_index'), -1) >= index:
                    continue
                if not _controls_may_coexecute(risk_event.get('controls'), record.get('controls')):
                    continue
                handle = str(risk_event.get('variable') or '')
                emitted = False
                for alias_name in risk_event.get('object_aliases') or []:
                    if alias_name == handle:
                        continue
                    # The alias must still reference the object at this point
                    # (pre-assignment view): a real refresh breaks the chain.
                    if pre_aliases.get(alias_name) != object_id:
                        continue
                    if not re.search(rf'\b{re.escape(alias_name)}\b', code):
                        continue
                    if assignment and assignment[0] == alias_name and alias_name not in assignment[1]:
                        continue  # pure refresh of the alias, not a use
                    if not _pointer_consuming_use(code, alias_name):
                        continue
                    use_event = make_event('USE', record, alias_name, object_id)
                    use_event['evidence_status'] = 'observation'
                    use_event['ordering_note'] = (
                        f'analyzer ordering: the release-named call on `&{handle}` precedes '
                        f'this use of the alias `{alias_name}`; the callee can clear only '
                        f'`{handle}`, and no reassignment of `{alias_name}` recognized by '
                        'the analyzer intervenes'
                    )
                    suspect_candidates.append({
                        'kind': 'stale_pointer_suspect',
                        'variable': alias_name,
                        'object': object_id,
                        'evidence_status': 'observation',
                        'effect_strength': risk_event.get('effect_strength', 'exact_owner'),
                        'use_strength': _pointer_use_strength(code, alias_name),
                        'events': [risk_event, use_event],
                    })
                    emitted = True
                    break
                if emitted:
                    addr_release_risk.pop(object_id, None)

    # Cross-call persistent-field observations (P2): a proven release whose
    # referent stays reachable through a never-cleared persistent field.
    suspect_candidates.extend(
        _field_dangling_observations(
            records, function_code, function_name, language,
            caller_names=caller_names,
            externally_invoked=externally_invoked,
        )
    )

    # Lock/flag double-entry race anchors. Suppressed when every in-file call
    # site of this function runs under a common caller-held lock (the flag
    # accesses are then serialized, e.g. the patched CVE-2017-10661 wrapper).
    if not caller_serialized:
        suspect_candidates.extend(
            _lock_flag_race_observations(function_code, function_name)
        )

    # Rank observation suspects and apply the per-function cap AFTER collection:
    # one per distinct abstract object first, then by evidence strength
    # (summary-proven release > exact-owner opaque > ancestor/bare-macro),
    # then strong uses (deref/member/subscript/arithmetic) before weak ones
    # (opaque call argument / return), earliest first as the final tie-break.
    if suspect_candidates:
        _strength_rank = {'summary_proven': 0, 'exact_owner': 1}

        def _suspect_rank(candidate: dict[str, Any]) -> tuple:
            kind_tier = (
                0
                if candidate['kind'] in ('release_overlap_suspect', 'field_dangling_suspect')
                else 1
            )
            strength_tier = _strength_rank.get(candidate.get('effect_strength'), 2)
            use_tier = 0 if candidate.get('use_strength') == 'strong' else 1
            first_index = min(
                (_safe_int(event.get('statement_index'), 0) for event in candidate['events']),
                default=0,
            )
            return (kind_tier, strength_tier, use_tier, first_index)

        by_object: dict[str, list[dict[str, Any]]] = {}
        for suspect in suspect_candidates:
            by_object.setdefault(str(suspect.get('object') or ''), []).append(suspect)
        pools = [sorted(group, key=_suspect_rank) for group in by_object.values()]
        picked: list[dict[str, Any]] = []
        for pool in pools:
            if pool:
                picked.append(pool.pop(0))
        picked.extend(sorted(
            (suspect for pool in pools for suspect in pool),
            key=_suspect_rank,
        ))
        candidates.extend(picked[:_STALE_OBS_MAX_PER_FUNCTION])

    output: list[dict[str, Any]] = []
    seen = set()
    for candidate in candidates:
        events = sorted(candidate['events'], key=lambda item: (
            _safe_int(item.get('statement_index'), 0),
            _safe_int(item.get('start_byte'), -1),
            item.get('event_kind', ''),
        ))
        signature = (
            candidate['kind'], candidate['object'],
            tuple((event.get('event_kind'), event.get('start_byte'), event.get('variable')) for event in events),
        )
        if signature in seen:
            continue
        seen.add(signature)
        terminal = events[-1]
        output.append({
            'path_kind': 'lifecycle',
            'source_variable': [candidate['variable']],
            'source_type': 'lifecycle_pointer',
            'taint_source': [events[0]['code']],
            'source_from_function': [function_name],
            'abstract_object': candidate['object'],
            'lifecycle_kind': candidate['kind'],
            'lifecycle_events': events,
            'sinks': [{
                'code': terminal['code'],
                'category': (
                    'lifecycle_use' if candidate['kind'] == 'use_after_free'
                    else 'double_release' if candidate['kind'] == 'double_free'
                    else 'lifecycle_suspect'
                ),
                'evidence_status': candidate.get('evidence_status', 'complete'),
                # Field-family (obj->cur/base/end/...) and macro-value object ids
                # are best-effort identities, not proven aliasing; the LLM stages
                # must not treat a shared id as a proven same-object fact.
                'object_identity': (
                    candidate.get('object_identity')
                    or (
                        'macro_opaque' if str(candidate['object']).startswith('macro::')
                        else 'field_family_inferred'
                        if ('::buffer' in str(candidate['object']) or '::storage' in str(candidate['object']))
                        else 'explicit'
                    )
                ),
                'control_dependence': terminal.get('controls', []),
                # [SHADOW] structured guard/event facts: purely additive fields, existing logic untouched
                'guard_facts': guard_facts_at_byte(
                    function_code, _safe_int(terminal.get('start_byte'), -1)),
                'event_sequence': _lifecycle_event_sequence(events, function_code),
                'start_byte': _safe_int(terminal.get('start_byte'), -1),
                'object_id': candidate['object'],
                'branch_signature': terminal.get('branch_signature', []),
            }],
            'analysis_summary': {
                'event_count': len(events),
                'lifecycle_kind': candidate['kind'],
                'abstract_object': candidate['object'],
                'same_object_ordered': True,
            },
        })
        if max_candidates is not None and len(output) >= max_candidates:
            break
    return output


# --- CWE-476 nullable-origin candidates --------------------------------------
# Optional per-function cap on emitted nullable origins, DISABLED by default
# (0 = unlimited). With budget-aware pre-aggregation downstream, the cap was
# measured to cost recall (118 dropped paths on CVE-2018-1000039) while leaving
# final LLM task counts unchanged, so it now only acts as an explicit
# low-budget mode (see ACTION_LOG_2026-08-09, GPT third review section 2).
_NULLABLE_MAX_ORIGINS_PER_FUNCTION = max(
    0, int(os.environ.get('VUL_NULLABLE_MAX_ORIGINS', '0') or '0')
)

# Experimental: container-growth sibling-field UAF inference. The alias between
# a sibling pointer field and the grown container's backing storage is inferred,
# not established in-file; events are explicitly marked as heuristic for the
# verifier. DISABLED by default: the alias relation is not proven statically,
# so this stays an opt-in recall experiment until its precision is measured.
# Set VUL_SIBLING_UAF=1 to enable for ablation.
_SIBLING_UAF_INFERENCE = os.environ.get('VUL_SIBLING_UAF', '0').strip().lower() not in {'0', 'false', 'off'}

# Observation-level stale-pointer / release-overlap evidence. These candidates
# are explicitly marked heuristic/observation and never suppress completed
# candidates; they exist so the LLM stages receive an anchor when the decisive
# event hides behind an opaque call or macro. Set VUL_STALE_PTR_OBS=0 to disable
# for ablation; VUL_STALE_OBS_MAX caps observations per function.
_STALE_POINTER_OBS_ENABLED = os.environ.get('VUL_STALE_PTR_OBS', '1').strip().lower() not in {'0', 'false', 'off'}
_STALE_OBS_MAX_PER_FUNCTION = max(0, int(os.environ.get('VUL_STALE_OBS_MAX', '3') or '3'))
_KNOWN_PURE_CALLEE = re.compile(
    r'^(?:strlen|strcmp|strncmp|strcasecmp|strncasecmp|memcmp|memchr|strchr|'
    r'strrchr|strstr|xmlStrlen|xmlStrcmp|xmlStrncmp|xmlStrEqual|xmlStrcasecmp|'
    r'isalpha|isdigit|isalnum|isspace|isupper|islower|toupper|tolower|'
    r'abs|labs|min|max)$',
    flags=re.I,
)


def analyze_null_deref_candidates(function_code: str, func_name: str = '') -> list:
    """Detect CWE-476 nullable-origin patterns the alias machinery cannot see.

    N1: a local pointer variable assigned/initialized from a call is later
    dereferenced (`x->f`, `*x`, `x[i]`). An intervening textual NULL check no
    longer suppresses the candidate (it may not dominate the dereference);
    it is attached as a neutral static note for the verifier instead.
    N2: a call result is dereferenced inline inside a larger
    expression (`f(...)->field`, `*f(...)`, `f(...)[i]`).

    Returns a list of dicts shaped like analyze_taint_paths success results
    plus `path_kind: 'nullable_origin'`. Any internal error yields [].
    """
    try:
        tree = _function_tree_cached(function_code, 'c')
    except Exception:
        return []
    try:
        root_node = tree.root_node
        source_text = function_code or ''

        def stmt_code(stmt: Node) -> str:
            return re.sub(r'\s+', ' ', _node_text(stmt).strip())

        def unwrap_to_call(node: Node | None) -> Node | None:
            current = node
            while current is not None:
                if current.type == 'call_expression':
                    return current
                if current.type in {'cast_expression', 'parenthesized_expression'}:
                    named = [c for c in current.children if c.is_named]
                    current = named[0] if named else None
                    continue
                break
            return None

        def call_name(call_node: Node) -> str:
            fn = call_node.child_by_field_name('function')
            return _node_text(fn) if fn is not None else '[unknown_function]'

        def observed_null_check(var_name: str, start_byte: int, end_byte: int) -> str | None:
            # A textual NULL check in the region before the dereference does
            # NOT prove the dereference is guarded: the check may sit on an
            # incompatible branch, precede a reassignment, or simply not
            # dominate the sink. Keep the candidate and report the check as a
            # neutral static fact; dominance is for the verifier to decide.
            # IS_ERR_OR_NULL excludes NULL as well; a bare IS_ERR does NOT
            # (handled below as an explicit insufficiency note).
            region = source_text[start_byte:end_byte]
            esc = re.escape(var_name)
            patterns = [
                rf'if\s*\(\s*!\s*{esc}\b',
                rf'if\s*\(\s*{esc}\s*==\s*NULL\b',
                rf'if\s*\(\s*NULL\s*==\s*{esc}\b',
                rf'if\s*\(\s*{esc}\s*!=\s*NULL\b',
                rf'if\s*\(\s*NULL\s*!=\s*{esc}\b',
                rf'if\s*\(\s*{esc}\s*\)',
                rf'IS_ERR_OR_NULL\s*\(\s*{esc}\s*\)',
            ]
            if any(re.search(pattern, region) for pattern in patterns):
                return (
                    f"static note: observed prior NULL check on {var_name}; "
                    f"whether it dominates this dereference on the current path "
                    f"is for the verifier to decide"
                )
            return None

        def insufficient_iserr_check(var_name: str, start_byte: int, end_byte: int) -> str | None:
            """Neutral static fact when a prior IS_ERR check is observed: IS_ERR
            excludes ERR_PTR values but not NULL (e.g. crypto_get_attr_type can
            return NULL without an error code). Dominance over the dereference is
            for the verifier to decide, not claimed here."""
            region = source_text[start_byte:end_byte]
            esc = re.escape(var_name)
            if re.search(rf'\bIS_ERR\s*\(\s*{esc}\s*\)', region):
                return (
                    f"static note: observed prior IS_ERR({var_name}) check; "
                    f"IS_ERR excludes ERR_PTR values but does not exclude NULL"
                )
            return None

        def deref_base_identifier(node: Node) -> Node | None:
            # Identifier dereferenced at a `->` / `*` / `[]` site, if any.
            if node.type in {'field_expression', 'subscript_expression'}:
                base = node.child_by_field_name('argument')
            elif node.type == 'pointer_expression':
                first = node.child(0)
                if first is None or first.type != '*':
                    return None
                named = [c for c in node.children if c.is_named]
                base = named[0] if named else None
            else:
                return None
            if base is not None and base.type == 'identifier':
                return base
            return None

        # --- Pass 1: collect N1 origins (local pointer = call result) ---
        origins: dict[str, dict[str, Any]] = {}
        q = deque([root_node])
        while q:
            node = q.popleft()
            lhs_node = rhs_node = None
            if node.type == 'assignment_expression':
                lhs_node = node.child_by_field_name('left')
                rhs_node = node.child_by_field_name('right')
                target = lhs_node if lhs_node is not None and lhs_node.type == 'identifier' else None
            elif node.type == 'init_declarator':
                lhs_node = node.child_by_field_name('declarator')
                rhs_node = node.child_by_field_name('value')
                # Unwrap pointer/array/parenthesized declarators to the name.
                target = lhs_node
                while target is not None and target.type != 'identifier':
                    target = target.child_by_field_name('declarator')
            else:
                target = None
            if target is not None and rhs_node is not None:
                call_node = unwrap_to_call(rhs_node)
                if call_node is not None:
                    var_name = _node_text(target)
                    if var_name and var_name not in origins:
                        stmt = _get_enclosing_statement(node) or node
                        try:
                            var_type = _get_variable_c_type(root_node, var_name)
                        except Exception:
                            var_type = ''
                        # Local pointer variables only.
                        if '*' in (var_type or ''):
                            origins[var_name] = {
                                'code': stmt_code(stmt),
                                'callee': call_name(call_node),
                                'end_byte': stmt.end_byte,
                                'type': var_type,
                            }
            q.extend(node.children)

        # --- Pass 2: collect dereference sinks, grouped per origin ---
        groups: dict[tuple, dict[str, Any]] = {}
        seen_sink_bytes: set[int] = set()

        def add_sink(group_key, group_seed, deref_node, stmt):
            if stmt.start_byte in seen_sink_bytes:
                return
            seen_sink_bytes.add(stmt.start_byte)
            group = groups.setdefault(group_key, {**group_seed, 'sinks': []})
            # [SHADOW] N1's tracked variable is the nullable origin variable; N2 (inline call result)
            # has no trackable variable, so event_sequence conservatively gets []
            tracked_var = group_key[1] if group_key[0] == 'N1' else None
            group['sinks'].append({
                'code': stmt_code(stmt),
                'category': 'Potential NULL Dereference',
                'control_dependence': _find_control_dependencies(deref_node),
                # [SHADOW] structured guard/event facts: purely additive fields, existing logic untouched
                'guard_facts': _find_control_guard_facts(deref_node),
                'event_sequence': sink_event_sequence(
                    function_code, stmt.start_byte,
                    [tracked_var] if tracked_var else [],
                    canonical_object=tracked_var, primary_var=tracked_var),
                'start_byte': stmt.start_byte,
            })

        q = deque([root_node])
        while q:
            node = q.popleft()

            # N1: dereference of a tracked nullable-origin variable.
            base = deref_base_identifier(node)
            if base is not None:
                var_name = _node_text(base)
                origin = origins.get(var_name)
                if origin is not None and node.start_byte >= origin['end_byte']:
                    stmt = _get_enclosing_statement(node) or node
                    if stmt.start_byte >= origin['end_byte']:
                        add_sink(('N1', var_name), {
                            'source_variable': [var_name],
                            'source_type': origin['type'],
                            'taint_source': [origin['code']],
                            'source_from_function': [origin['callee']],
                        }, node, stmt)
                        notes = [
                            note for note in (
                                observed_null_check(
                                    var_name, origin['end_byte'], stmt.start_byte
                                ),
                                insufficient_iserr_check(
                                    var_name, origin['end_byte'], stmt.start_byte
                                ),
                            )
                            if note
                        ]
                        if notes:
                            group = groups.get(('N1', var_name))
                            if group and group['sinks']:
                                last = group['sinks'][-1]
                                # add_sink may have skipped a duplicate stmt.
                                if last.get('start_byte') == stmt.start_byte:
                                    # [FIX] Non-guard note text must not be mixed into control_dependence
                                    # (that field's semantics is "control conditions dominating the sink");
                                    # it goes into the separate static_notes field for downstream use
                                    snotes = last.setdefault('static_notes', [])
                                    if isinstance(snotes, list):
                                        snotes.extend(notes)

            # N2: inline dereference of a call result.
            call_base = None
            if node.type in {'field_expression', 'subscript_expression'}:
                call_base = unwrap_to_call(node.child_by_field_name('argument'))
            elif node.type == 'pointer_expression':
                first = node.child(0)
                if first is not None and first.type == '*':
                    named = [c for c in node.children if c.is_named]
                    call_base = unwrap_to_call(named[0] if named else None)
            if call_base is not None:
                stmt = _get_enclosing_statement(node) or node
                callee = call_name(call_base)
                add_sink(('N2', call_base.start_byte), {
                    'source_variable': [callee],
                    'source_type': 'nullable_call_result',
                    'taint_source': [_node_text(call_base)],
                    'source_from_function': [callee],
                }, node, stmt)

            q.extend(node.children)

        # --- Emit one result dict per distinct nullable origin ---
        # Origins carrying an IS_ERR-insufficiency note rank first (strongest
        # nullability signal), then by sink coverage. Emission is uncapped by
        # default; VUL_NULLABLE_MAX_ORIGINS>0 enables an explicit low-budget
        # per-function cap (see _NULLABLE_MAX_ORIGINS_PER_FUNCTION).
        def _group_priority(item: tuple) -> tuple:
            group_key, group = item
            notes = [
                str(note)
                for sink in group['sinks']
                for note in (sink.get('static_notes') or [])
            ]
            has_insufficiency = any('does not exclude NULL' in note for note in notes)
            has_null_check = any('observed prior NULL check' in note for note in notes)
            return (not has_insufficiency, has_null_check, -len(group['sinks']), str(group_key))

        ranked_groups = [
            (key, groups[key]) for key in sorted(groups, key=lambda k: (k[0], str(k[1])))
        ]
        ranked_groups.sort(key=_group_priority)
        if _NULLABLE_MAX_ORIGINS_PER_FUNCTION > 0:
            ranked_groups = ranked_groups[:_NULLABLE_MAX_ORIGINS_PER_FUNCTION]

        output: list[dict[str, Any]] = []
        for group_key, group in ranked_groups:
            sinks = sorted(group['sinks'], key=lambda item: item['start_byte'])
            if not sinks:
                continue
            output.append({
                'source_variable': group['source_variable'],
                'source_type': group['source_type'],
                'taint_source': group['taint_source'],
                'source_from_function': group['source_from_function'],
                'sinks': sinks,
                'analysis_summary': {
                    'origin_kind': group_key[0],
                    'sink_count': len(sinks),
                    'function': func_name,
                    'source_strategy': 'nullable_origin_heuristic',
                },
                'path_kind': 'nullable_origin',
            })
        return output
    except Exception:
        return []


_COND_INIT_MAX_PER_FUNCTION = _safe_int(os.environ.get('VUL_COND_INIT_MAX', '3'), 3)


def analyze_conditional_init_candidates(function_code: str, func_name: str = '') -> list:
    """N3: conditional-definition nullable origins (state-style CWE-476 roots).

    Shape: a local pointer is NULL-initialized (or left uninitialized) and its
    only definitions are conditional (guard-controlled) assignments; a later
    dereference has no dominating NULL check / early-exit on the variable and
    no unconditional redefinition in between. Patch-side suppression is
    structural: an added dominating ``if (!p) return`` removes the candidate.

    Returns dicts shaped like analyze_null_deref_candidates results with
    origin_kind 'N3'. Any internal error yields [].
    """
    try:
        tree = _function_tree_cached(function_code, 'c')
    except Exception:
        return []
    try:
        root_node = tree.root_node
        source_text = function_code or ''

        def stmt_code(stmt: Node) -> str:
            return re.sub(r'\s+', ' ', _node_text(stmt).strip())

        def is_null_constant(text: str) -> bool:
            # Pointer casts may be multi-word: `(unsigned char *) NULL`,
            # `(struct foo *) NULL`. Scalar-only casts are not stripped.
            stripped = re.sub(
                r'^(?:\([A-Za-z_][\w\s]*\*+\s*\)\s*)+', '', text.strip(),
            )
            return bool(re.fullmatch(r'(?:NULL|nullptr|0)', stripped))

        def guard_null_polarity(condition_text: str, var_name: str) -> str | None:
            """Canonicalize a guard to 'nonnull' / 'null' for `var_name`, else None.

            Handles cast spellings (`p == (unsigned char *) NULL`), bare truthy
            (`if (p)`), and negation (`!p`, `!(p == NULL)`); the negated null
            check guarding an else-branch canonicalizes to 'nonnull'."""
            text = re.sub(r'\s+', '', str(condition_text or '')).lower()
            text = re.sub(r'^(?:if|while|for)\(', '(', text)
            negated = False
            changed = True
            while changed and text:
                changed = False
                if text.startswith('!'):
                    negated = not negated
                    text = text[1:]
                    changed = True
                while len(text) >= 2 and text[0] == '(' and text[-1] == ')':
                    text = text[1:-1]
                    changed = True
            # Strip pointer casts left around NULL spellings.
            text = re.sub(r'\([a-z_][\w\s]*\*+\)', '', text)
            v = var_name.lower()
            polarity = None
            match = re.fullmatch(r'([a-z_]\w*)(==|!=)(null|nullptr|0)', text)
            swap = re.fullmatch(r'(null|nullptr|0)(==|!=)([a-z_]\w*)', text)
            if match and match.group(1) == v:
                polarity = 'nonnull' if match.group(2) == '!=' else 'null'
            elif swap and swap.group(3) == v:
                polarity = 'nonnull' if swap.group(2) == '!=' else 'null'
            elif text == v:
                polarity = 'nonnull'
            if polarity is None:
                return None
            if negated:
                polarity = 'null' if polarity == 'nonnull' else 'nonnull'
            return polarity

        def normalized_controls(node: Node) -> set[str]:
            return {
                _normalize_guard_atom(item)
                for item in _find_control_dependencies(node)
                if _normalize_guard_atom(item)
            }

        def _strip_outer_parens(text: str) -> str:
            while len(text) >= 2 and text[0] == '(' and text[-1] == ')':
                depth = 0
                balanced_outer = True
                for i, ch in enumerate(text):
                    if ch == '(':
                        depth += 1
                    elif ch == ')':
                        depth -= 1
                        if depth == 0 and i < len(text) - 1:
                            balanced_outer = False
                            break
                if not balanced_outer:
                    break
                text = text[1:-1]
            return text

        def _split_top_level(text: str, op: str) -> list[str]:
            text = _strip_outer_parens(re.sub(r'\s+', '', text))
            parts: list[str] = []
            depth = 0
            current: list[str] = []
            i = 0
            while i < len(text):
                ch = text[i]
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                if depth == 0 and text.startswith(op, i):
                    parts.append(''.join(current))
                    current = []
                    i += 2
                    continue
                current.append(ch)
                i += 1
            parts.append(''.join(current))
            return [part for part in parts if part]

        def guard_says_nonnull(condition_text: str, var_name: str) -> bool:
            # A top-level `&&` conjunct asserting `p != NULL` dominates every
            # later conjunct and the guarded branch.
            return any(
                guard_null_polarity(part, var_name) == 'nonnull'
                for part in _split_top_level(str(condition_text or ''), '&&')
            )

        def guard_says_null_exit(condition_text: str, var_name: str) -> bool:
            # Exiting on `(p == NULL || ...)` guarantees `p != NULL` on the
            # fall-through path.
            return any(
                guard_null_polarity(part, var_name) == 'null'
                for part in _split_top_level(str(condition_text or ''), '||')
            )

        def has_nonnull_guard(var_name: str, node: Node) -> bool:
            """True when a control dependency of `node` canonically asserts
            `var_name != NULL` (including else-branches of `p == NULL` and
            `&&`-conjoined checks)."""
            return any(
                guard_says_nonnull(item, var_name)
                for item in _find_control_dependencies(node)
            )

        def conjunction_nonnull_guard(var_name: str, node: Node) -> bool:
            """Short-circuit guard inside the same condition: `node` sits in
            the right operand of `A && B` where A asserts `var_name != NULL`
            (e.g. `if ((p != NULL) && (strncmp(p, ...)))`)."""
            ancestor = node.parent
            while ancestor is not None:
                if ancestor.type == 'binary_expression':
                    operator = ancestor.child_by_field_name('operator')
                    op_text = _node_text(operator) if operator is not None else ''
                    if op_text == '&&':
                        left = ancestor.child_by_field_name('left')
                        right = ancestor.child_by_field_name('right')
                        if (
                            left is not None and right is not None
                            and right.start_byte <= node.start_byte
                            and node.end_byte <= right.end_byte
                            and guard_says_nonnull(_node_text(left), var_name)
                        ):
                            return True
                ancestor = ancestor.parent
            return False

        def null_check_condition(condition_text: str, var_name: str) -> bool:
            return guard_says_null_exit(condition_text, var_name)

        def dominating_null_exit(var_name: str, from_byte: int, deref_node: Node) -> str | None:
            """Structural early-exit dominance: an `if (!p) return/...` whose parent
            compound statement is an ancestor of the dereference and precedes it.
            A check nested in a side branch (e.g. inside `if (x) { ... }`) does NOT
            dominate a later top-level use and must not suppress the candidate."""
            probe = deque([root_node])
            while probe:
                node = probe.popleft()
                if node.type == 'if_statement' and node.start_byte >= from_byte and node.end_byte <= deref_node.start_byte:
                    condition = node.child_by_field_name('condition')
                    if condition is not None and null_check_condition(_node_text(condition), var_name):
                        consequence = node.child_by_field_name('consequence')
                        exits = False
                        if consequence is not None:
                            stack = [consequence]
                            while stack:
                                current = stack.pop()
                                if current.type in {
                                    'return_statement', 'goto_statement',
                                    'break_statement', 'continue_statement',
                                }:
                                    exits = True
                                    break
                                # Never-return error/throw macros (ImageMagick
                                # ThrowReaderException-style) exit via longjmp.
                                if current.type == 'call_expression':
                                    callee_node = current.child_by_field_name('function')
                                    callee_text = _node_text(callee_node) if callee_node is not None else ''
                                    if re.search(
                                        r'(?i)(throw|assert|abort|exit|longjmp|fatal|raise|panic|\bbug)',
                                        callee_text,
                                    ):
                                        exits = True
                                        break
                                stack.extend(current.children)
                        if exits:
                            parent = node.parent
                            if parent is not None and parent.type in {
                                'compound_statement', 'translation_unit',
                            }:
                                # Node wrappers are not identity-stable in the
                                # binding; compare byte ranges instead of `is`.
                                parent_span = (parent.type, parent.start_byte, parent.end_byte)
                                ancestor = deref_node
                                holder = None
                                while ancestor is not None:
                                    ap = ancestor.parent
                                    if ap is not None and (
                                        ap.type, ap.start_byte, ap.end_byte
                                    ) == parent_span:
                                        holder = ancestor
                                        break
                                    ancestor = ap
                                if holder is not None and node.end_byte <= holder.start_byte:
                                    return stmt_code(node)
                probe.extend(node.children)
            return None

        def _unwrap_to_identifier(node: Node) -> Node | None:
            """Descend through casts/parens: `(char *) data` -> `data`."""
            current = node
            while current is not None:
                if current.type == 'identifier':
                    return current
                if current.type == 'cast_expression':
                    current = current.child_by_field_name('value')
                elif current.type == 'parenthesized_expression':
                    named = [c for c in current.children if c.is_named]
                    current = named[0] if named else None
                else:
                    return None
            return None

        def _inside_sizeof(node: Node) -> bool:
            ancestor = node.parent
            while ancestor is not None:
                if ancestor.type == 'sizeof_expression':
                    return True
                ancestor = ancestor.parent
            return False

        # --- Single traversal: collect ordered definition/use events per variable ---
        events: list[dict[str, Any]] = []
        q = deque([root_node])
        while q:
            node = q.popleft()
            if node.type == 'init_declarator':
                declarator = node.child_by_field_name('declarator')
                value = node.child_by_field_name('value')
                target = declarator
                while target is not None and target.type != 'identifier':
                    target = target.child_by_field_name('declarator')
                if target is not None:
                    var_name = _node_text(target)
                    try:
                        var_type = _get_variable_c_type(root_node, var_name)
                    except Exception:
                        var_type = ''
                    if var_name and '*' in (var_type or ''):
                        stmt = _get_enclosing_statement(node) or node
                        if value is not None and is_null_constant(_node_text(value)):
                            events.append({
                                'kind': 'null_set', 'var': var_name,
                                'byte': stmt.end_byte, 'code': stmt_code(stmt),
                                'type': var_type, 'origin': 'null_init',
                            })
                        elif value is not None:
                            events.append({
                                'kind': 'assign', 'var': var_name,
                                'byte': stmt.end_byte, 'code': stmt_code(stmt),
                                'controls': normalized_controls(node),
                            })
            elif node.type == 'declaration':
                has_value = any(
                    child.type == 'init_declarator'
                    and child.child_by_field_name('value') is not None
                    for child in node.children
                )
                if not has_value and '*' in _node_text(node):
                    for child in node.children:
                        target = child
                        if child.type == 'init_declarator':
                            target = child.child_by_field_name('declarator')
                        while target is not None and target.type != 'identifier':
                            target = target.child_by_field_name('declarator')
                        if target is None:
                            continue
                        var_name = _node_text(target)
                        if not var_name:
                            continue
                        try:
                            var_type = _get_variable_c_type(root_node, var_name)
                        except Exception:
                            var_type = ''
                        if '*' not in (var_type or ''):
                            continue
                        stmt = _get_enclosing_statement(node) or node
                        events.append({
                            'kind': 'null_set', 'var': var_name,
                            'byte': stmt.end_byte, 'code': stmt_code(stmt),
                            'type': var_type, 'origin': 'uninitialized',
                        })
            elif node.type == 'assignment_expression':
                lhs = node.child_by_field_name('left')
                rhs = node.child_by_field_name('right')
                if lhs is not None and lhs.type == 'identifier':
                    var_name = _node_text(lhs)
                    stmt = _get_enclosing_statement(node) or node
                    if rhs is not None and is_null_constant(_node_text(rhs)):
                        try:
                            var_type = _get_variable_c_type(root_node, var_name)
                        except Exception:
                            var_type = ''
                        if '*' in (var_type or ''):
                            events.append({
                                'kind': 'null_set', 'var': var_name,
                                'byte': stmt.end_byte, 'code': stmt_code(stmt),
                                'type': var_type, 'origin': 'null_init',
                            })
                    else:
                        events.append({
                            'kind': 'assign', 'var': var_name,
                            'byte': stmt.end_byte, 'code': stmt_code(stmt),
                            'controls': normalized_controls(node),
                        })
            # Dereference or pointer-consuming call argument.
            use_targets: list[Node] = []
            if node.type in {'field_expression', 'subscript_expression'}:
                candidate = node.child_by_field_name('argument')
                if candidate is not None and candidate.type == 'identifier':
                    use_targets.append(candidate)
            elif node.type == 'pointer_expression':
                first = node.child(0)
                named = [c for c in node.children if c.is_named]
                if first is not None and first.type == '*' and named and named[0].type == 'identifier':
                    use_targets.append(named[0])
            elif node.type == 'call_expression':
                arguments = node.child_by_field_name('arguments')
                if arguments is not None:
                    callee_node = node.child_by_field_name('function')
                    callee_text = _node_text(callee_node) if callee_node is not None else ''
                    # Release-style sinks consume NULL safely by near-universal
                    # convention (free/kfree/Relinquish.../Destroy...); passing
                    # a maybe-NULL pointer to them is not a dereference.
                    if not re.search(
                        r'(?i)(free|release|relinquish|destroy|dealloc|unref|dispose)',
                        callee_text,
                    ):
                        for child in arguments.children:
                            unwrapped = _unwrap_to_identifier(child)
                            if unwrapped is not None:
                                use_targets.append(unwrapped)
            if use_targets:
                # sizeof operands are unevaluated; `sizeof(*p)` is not a use.
                if not _inside_sizeof(node):
                    stmt = _get_enclosing_statement(node) or node
                    for use_target in use_targets:
                        events.append({
                            'kind': 'use', 'var': _node_text(use_target),
                            'byte': stmt.start_byte, 'stmt': stmt, 'node': node,
                        })
            q.extend(node.children)

        # --- Replay in byte order with a may-be-null state machine ---
        events.sort(key=lambda item: item['byte'])
        state: dict[str, bool] = {}
        null_since: dict[str, int] = {}
        origin_info: dict[str, dict[str, Any]] = {}
        cond_def_guards: dict[str, list[str]] = {}
        cond_assign_controls: dict[str, list[set[str]]] = {}
        groups: dict[str, dict[str, Any]] = {}
        seen_sink_bytes: set[int] = set()
        for event in events:
            var_name = event['var']
            if event['kind'] == 'null_set':
                state[var_name] = True
                null_since[var_name] = event['byte']
                origin_info.setdefault(var_name, event)
                cond_def_guards[var_name] = []
                cond_assign_controls[var_name] = []
            elif event['kind'] == 'assign':
                if state.get(var_name) is None:
                    continue
                if event['controls']:
                    # Conditional definition preserves the prior nullable state.
                    cond_assign_controls.setdefault(var_name, []).append(
                        event['controls']
                    )
                    if state.get(var_name):
                        cond_def_guards.setdefault(var_name, []).append(
                            ' && '.join(sorted(event['controls']))
                        )
                else:
                    # Unconditional fresh definition: defined on all paths from
                    # here (a nullable call result is the N1 pass's domain).
                    state[var_name] = False
                    cond_assign_controls[var_name] = []
            elif event['kind'] == 'use':
                if not state.get(var_name):
                    continue
                stmt = event['stmt']
                if stmt.start_byte in seen_sink_bytes:
                    continue
                if has_nonnull_guard(var_name, event['node']):
                    continue
                if conjunction_nonnull_guard(var_name, event['node']):
                    continue
                # Same-guard-region redefinition: a conditional definition
                # whose guards are all implied by this use's guards executes on
                # every path reaching the use (syntactic, best-effort), so the
                # variable is defined here.
                use_controls = normalized_controls(event['node'])
                if any(
                    assign_controls
                    and assign_controls <= use_controls
                    for assign_controls in cond_assign_controls.get(var_name, [])
                ):
                    continue
                exit_note = dominating_null_exit(
                    var_name, null_since.get(var_name, 0), stmt,
                )
                if exit_note is not None:
                    continue
                seen_sink_bytes.add(stmt.start_byte)
                origin = origin_info[var_name]
                guard_text = ' || '.join(dict.fromkeys(cond_def_guards.get(var_name) or []))[:200]
                origin_desc = (
                    'initialized to NULL'
                    if origin.get('origin') == 'null_init'
                    else 'declared without initializer'
                )
                group = groups.setdefault(var_name, {
                    'source_variable': [var_name],
                    'source_type': origin.get('type', ''),
                    'taint_source': [origin['code']],
                    'source_from_function': [func_name] if func_name else [],
                    'sinks': [],
                })
                group['sinks'].append({
                    'code': stmt_code(stmt),
                    'category': 'Potential NULL Dereference',
                    'control_dependence': _find_control_dependencies(event['node']),
                    'guard_facts': _find_control_guard_facts(event['node']),
                    'event_sequence': sink_event_sequence(
                        function_code, stmt.start_byte, [var_name],
                        canonical_object=var_name, primary_var=var_name,
                    ),
                    'start_byte': stmt.start_byte,
                    'static_notes': [
                        f'conditional definition: `{var_name}` is {origin_desc}'
                        + (
                            f' and assigned only under guard(s) [{guard_text}]'
                            if guard_text else ''
                        )
                        + '; no dominating NULL check, early exit, or '
                        'unconditional redefinition before this dereference',
                    ],
                })

        output: list[dict[str, Any]] = []
        for var_name in sorted(groups):
            group = groups[var_name]
            sinks = sorted(group['sinks'], key=lambda item: item['start_byte'])
            if not sinks:
                continue
            output.append({
                'source_variable': group['source_variable'],
                'source_type': group['source_type'],
                'taint_source': group['taint_source'],
                'source_from_function': group['source_from_function'],
                'sinks': sinks,
                'analysis_summary': {
                    'origin_kind': 'N3',
                    'sink_count': len(sinks),
                    'function': func_name,
                    'source_strategy': 'conditional_init_nullable',
                },
                'path_kind': 'nullable_origin',
            })
        if _COND_INIT_MAX_PER_FUNCTION > 0:
            output = output[:_COND_INIT_MAX_PER_FUNCTION]
        return output
    except Exception:
        return []


def clear_analysis_caches() -> None:
    """Optional helper for very large batch runs."""
    _cached_file_graph_data.cache_clear()
    _cached_function_code_items.cache_clear()
    _cached_extract_filtered_local_variables.cache_clear()
    _cached_preanalysis_snapshot.cache_clear()
    _read_source_cached.cache_clear()
    _function_tree_cached.cache_clear()
    _macro_definition_index.cache_clear()
    _LIFECYCLE_MACRO_CACHE.clear()
    _FUNC_GOTO_SCAN_CACHE.clear()
    _EVENT_SCAN_CACHE.clear()
    _FUNC_RET_DEFS_CACHE.clear()


if __name__ == "__main__":

    code = """
int kvm_iommu_map_pages(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	gfn_t gfn, end_gfn;
	pfn_t pfn;
	int r = 0;
	struct iommu_domain *domain = kvm->arch.iommu_domain;
	int flags;

	/* check if iommu exists and in use */
	if (!domain)
		return 0;

	gfn     = slot->base_gfn;
	end_gfn = gfn + slot->npages;

	flags = IOMMU_READ;
	if (!(slot->flags & KVM_MEM_READONLY))
		flags |= IOMMU_WRITE;
	if (!kvm->arch.iommu_noncoherent)
		flags |= IOMMU_CACHE;


	while (gfn < end_gfn) {
		unsigned long page_size;

		/* Check if already mapped */
		if (iommu_iova_to_phys(domain, gfn_to_gpa(gfn))) {
			gfn += 1;
			continue;
		}

		/* Get the page size we could use to map */
		page_size = kvm_host_page_size(kvm, gfn);

		/* Make sure the page_size does not exceed the memslot */
		while ((gfn + (page_size >> PAGE_SHIFT)) > end_gfn)
			page_size >>= 1;

		/* Make sure gfn is aligned to the page size we want to map */
		while ((gfn << PAGE_SHIFT) & (page_size - 1))
			page_size >>= 1;

		/* Make sure hva is aligned to the page size we want to map */
		while (__gfn_to_hva_memslot(slot, gfn) & (page_size - 1))
			page_size >>= 1;

		/*
		 * Pin all pages we are about to map in memory. This is
		 * important because we unmap and unpin in 4kb steps later.
		 */
		pfn = kvm_pin_pages(slot, gfn, page_size);
		if (is_error_noslot_pfn(pfn)) {
			gfn += 1;
			continue;
		}

		/* Map into IO address space */
		r = iommu_map(domain, gfn_to_gpa(gfn), pfn_to_hpa(pfn),
			      page_size, flags);
		if (r) {
			printk(KERN_ERR "kvm_iommu_map_address:"
			       "iommu failed to map pfn=%llx\n", pfn);
			kvm_unpin_pages(kvm, pfn, page_size);
			goto unmap_pages;
		}

		gfn += page_size >> PAGE_SHIFT;


	}

	return 0;

unmap_pages:
	kvm_iommu_put_pages(kvm, slot->base_gfn, gfn - slot->base_gfn);
	return r;
}
}
"""
    # print(_pre_analyze_and_build_context(code))
    print("="*20 + " Analyzing variable: 'ife' " + "="*20)
    variable_to_trace = "page_size"
    # --- MODIFIED: use the new analyze_taint_paths ---
    results = analyze_taint_paths(code, variable_to_trace)
    
    # print("="*20 + " Analyzing parameter index 1: 'regs' " + "="*20)
    # --- MODIFIED: use the new analyze_taint_paths_by_param_index ---
    # results = analyze_taint_paths_by_param_index_new(code, 1)

    # results = extract_filtered_local_variables(code)
    # Print the results as pretty JSON
    print(json.dumps(results, indent=4))

    # local_vars = extract_local_variables(code)
    # print(local_vars)
    

    # file_to_test = '/path/to/your/test_file.c'
    # all_funcs = get_funcnames_from_file(file_to_test, language='c')
    
    # print('get_name' in all_funcs)
    # print('if_cache_add' in all_funcs)
    # print('xmalloc' in all_funcs)


    # get_code_from_file('fa_ambig_example',file_to_test)
    # print(f"--- Analyzing file: {file_to_test} ---")

    # # --- Call the new function to build the adjacency list ---
    # print("\n>>> 1. Build the adjacency-list call graph (for LangGraph)")
    # rooted_call_graphs = generate_rooted_call_graphs(file_to_test)
    
    # if rooted_call_graphs:
    #     print("\n[Result] Per-root call graph (the format LangGraph needs):")
    #     # Pretty-print with json.dumps
    #     print(json.dumps(rooted_call_graphs, indent=4))
    #     if 'fa_expand_nocase' in rooted_call_graphs:
    #         print("\nOnly the 'fa_expand_nocase' call graph:")
    #         main_subgraph = rooted_call_graphs['fa_expand_nocase']
    #         print(json.dumps(main_subgraph, indent=4))
    
    # print("\n" + "="*50 + "\n")

    # # --- Call the old function to generate Markdown ---
    # print(">>> 2. Generate the Markdown call graph (for human reading)")
    # markdown_graphs = generate_markdown_call_graph(file_to_test)
    # if markdown_graphs:
    #     print("\n[Result] Markdown call tree:")
    #     for root, tree in markdown_graphs.items():
    #         print(f"\n--- Tree for root: {root} ---")
    #         print(tree)

    #     # Show how to reference a graph directly by key
    #     print("\n--- Reference example ---")
    #     if "fa_expand_nocase" in markdown_graphs:
    #         print("Access the 'main' call graph directly:")
    #         print(markdown_graphs["fa_expand_nocase"])
    
    # os.remove(file_to_test)
