"""VEC deterministic counter-evidence retrieval core (zero LLM, purely static).

Shared by two callers: `vd_ultra_kimi.py` (verifier prompt injection, VUL_VEC_COUNTER_EVIDENCE)
and `src/vec_shadow.py` (shadow statistics). Only depends on the guard
normalization/variable-extraction primitives of tools.ts_sast_new_kimi; no reverse dependency on vd_ultra_kimi (avoids circular imports).

Honesty constraints (consistent with VEC_COUNTEREVIDENCE_SHADOW.md):
- function-level scanning knows no branch polarity/dominance, so guard scope is always UNKNOWN;
- variable matching uses direct root variable names, with no cross-variable alias propagation;
- no retrieval means no output; it is never phrased as "no counter-evidence exists".
"""

import re

import warnings
warnings.filterwarnings("ignore")

from tree_sitter import Language, Parser

from . import sast_backend as T

_LANGUAGE = Language(T.TREE_SITTER_SO_PATH, 'c')


def _parser() -> Parser:
    parser = Parser()
    parser.set_language(_LANGUAGE)
    return parser


def _safe_list(value):
    return list(value) if isinstance(value, (list, tuple)) else []


def _safe_int(value, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _norm_text(value: str) -> str:
    return ' '.join(str(value).split())


# Known length APIs: 0-based index of the length parameter (same convention as GuardFact role annotation)
LEN_ARG_INDEX = {
    'memcpy': 2, 'memmove': 2, 'memset': 2, 'strncpy': 2, 'strlcpy': 2,
    'strncat': 2, 'copy_to_user': 2, 'copy_from_user': 2, 'copy_to_iter': 2,
    'copy_from_iter': 2, 'skb_copy_bits': 3,
}
ALLOC_CALLEES = (
    'kmalloc', 'kzalloc', 'kcalloc', 'kmalloc_array', 'kvmalloc', 'krealloc',
    'vmalloc', 'vzalloc', 'alloc_skb', 'dev_kmalloc', 'devm_kmalloc',
    'devm_kzalloc', 'kmemdup', 'memdup_user', 'kmem_cache_alloc', 'malloc',
)
CHECKED_HELPERS = (
    'check_add_overflow', 'check_mul_overflow', 'check_sub_overflow',
    'size_add', 'size_mul', 'size_sub', 'array_size', 'struct_size',
    'kmalloc_array', 'kcalloc',  # built-in count*size overflow check
)
CLAMP_CALLEES = ('min', 'min_t', 'min3', 'clamp', 'clamp_t', 'clamp_val')
ARITH_OPS = ('+', '-', '*', '/', '%', '<<', '>>')
BOUNDS_CATEGORIES = {'Array Index', 'Array Base'}
INTEGER_CATEGORIES = {'Integer Arithmetic', 'Integer Control Use'}
LIFETIME_CATEGORIES = {'lifecycle_use', 'double_release', 'lifecycle_suspect'}


def _node_text(node) -> str:
    return node.text.decode('utf8', errors='ignore').strip()


def _root_var(text: str) -> str:
    """Extract the root variable name from texts like `p->f` / `a[i]` / `(*p)`."""
    match = re.search(r'[A-Za-z_]\w*', text or '')
    return match.group(0) if match else ''


# ---------------------------------------------------------------------------
# One pass per function: guard conditions / write events / capacity facts / checked helpers / clamps
# ---------------------------------------------------------------------------

def scan_function(code: str) -> dict:
    """Run one tree-sitter scan over a function code string, producing the VEC retrieval index."""
    result = {
        'conditions': [],   # {raw, normalized, vars, cond_byte}
        'ternary_conditions': [],  # ternary-expression conditions {raw, vars, cond_byte}
        'writes': [],       # {var, byte, kind}
        'capacities': [],   # {var, size_text, byte, callee}
        'helpers': [],      # {callee, byte}
        'clamps': [],       # {callee, args_text, byte, vars}
    }
    if not code:
        return result
    try:
        tree = _parser().parse(code.encode('utf-8'))
    except Exception:
        return result

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        ntype = node.type
        if ntype in ('if_statement', 'while_statement', 'for_statement',
                     'do_statement', 'switch_statement'):
            cond = node.child_by_field_name('condition')
            if cond is not None:
                result['conditions'].append({
                    'raw': _node_text(cond),
                    'normalized': T._guard_norm_expr(cond),
                    'vars': T._guard_condition_vars(cond),
                    'cond_byte': cond.start_byte,
                })
        elif ntype == 'assignment_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            if left is not None:
                lhs_text = re.sub(r'\s+', '', _node_text(left))
                result['writes'].append({'var': _root_var(_node_text(left)),
                                         'lhs': lhs_text,
                                         'byte': node.start_byte,
                                         'kind': 'assign'})
                call = T._guard_unwrap_to_call(right)
                if call is not None:
                    fn = call.child_by_field_name('function')
                    callee = _node_text(fn) if fn else ''
                    if callee in ALLOC_CALLEES:
                        args = call.child_by_field_name('arguments')
                        arg_nodes = [c for c in args.children if c.is_named] if args else []
                        size_text = _node_text(arg_nodes[0]) if arg_nodes else ''
                        if callee in ('kmalloc_array', 'kcalloc', 'calloc'):
                            size_text = ' * '.join(_node_text(a) for a in arg_nodes[:2])
                        result['capacities'].append({
                            'var': _root_var(_node_text(left)),
                            'size_text': size_text,
                            'byte': node.start_byte, 'callee': callee,
                        })
        elif ntype == 'init_declarator':
            target = node.child_by_field_name('declarator')
            while target is not None and target.type != 'identifier':
                nxt = target.child_by_field_name('declarator')
                if nxt is None or nxt == target:
                    target = None
                    break
                target = nxt
            if target is not None:
                var = _node_text(target)
                result['writes'].append({'var': var, 'lhs': var,
                                         'byte': node.start_byte,
                                         'kind': 'decl'})
                call = T._guard_unwrap_to_call(node.child_by_field_name('value'))
                if call is not None:
                    fn = call.child_by_field_name('function')
                    callee = _node_text(fn) if fn else ''
                    if callee in ALLOC_CALLEES:
                        args = call.child_by_field_name('arguments')
                        arg_nodes = [c for c in args.children if c.is_named] if args else []
                        size_text = _node_text(arg_nodes[0]) if arg_nodes else ''
                        if callee in ('kmalloc_array', 'kcalloc', 'calloc'):
                            size_text = ' * '.join(_node_text(a) for a in arg_nodes[:2])
                        result['capacities'].append({
                            'var': var, 'size_text': size_text,
                            'byte': node.start_byte, 'callee': callee,
                        })
        elif ntype == 'conditional_expression':
            cond = node.child_by_field_name('condition')
            if cond is not None:
                result['ternary_conditions'].append({
                    'raw': _node_text(cond),
                    'vars': T._guard_condition_vars(cond),
                    'cond_byte': cond.start_byte,
                })
        elif ntype == 'update_expression':
            result['writes'].append({'var': _root_var(_node_text(node)),
                                     'lhs': re.sub(r'\s+', '', _node_text(node)),
                                     'byte': node.start_byte, 'kind': 'update'})
        elif ntype == 'call_expression':
            fn = node.child_by_field_name('function')
            callee = _node_text(fn) if fn else ''
            args = node.child_by_field_name('arguments')
            arg_nodes = [c for c in args.children if c.is_named] if args else []
            if callee in CHECKED_HELPERS:
                result['helpers'].append({
                    'callee': callee, 'byte': node.start_byte,
                    'vars': [_root_var(_node_text(a)) for a in arg_nodes],
                })
            if callee in CLAMP_CALLEES:
                result['clamps'].append({
                    'callee': callee,
                    'args_text': [_node_text(a) for a in arg_nodes],
                    'vars': [_root_var(_node_text(a)) for a in arg_nodes],
                    'byte': node.start_byte,
                })
            for arg in arg_nodes:
                if arg.type == 'identifier':
                    result['writes'].append({'var': _node_text(arg),
                                             'lhs': _node_text(arg),
                                             'byte': node.start_byte,
                                             'kind': 'call_arg'})
        stack.extend(node.children)
    return result


# ---------------------------------------------------------------------------
# Sink key-variable extraction and family classification
# ---------------------------------------------------------------------------

def _parse_op(operation: str):
    try:
        tree = _parser().parse(f"void __vec_f(){{ {operation} ; }}".encode('utf-8'))
        return tree.root_node
    except Exception:
        return None


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def sink_key_vars(sink: dict, family: str) -> dict:
    """Return {'vars': [...], 'len_vars': [...], 'obj_vars': [...]} (role-split best effort)."""
    operation = str(sink.get('operation') or '')
    out = {'vars': [], 'len_vars': [], 'obj_vars': []}
    root = _parse_op(operation)
    if root is None:
        fallback = _root_var(operation)
        out['vars'] = [fallback] if fallback else []
        return out

    calls = [n for n in _walk(root) if n.type == 'call_expression']
    subscripts = [n for n in _walk(root) if n.type == 'subscript_expression']

    if family == 'bounds':
        for call in calls:
            fn = call.child_by_field_name('function')
            callee = _node_text(fn) if fn else ''
            if callee in LEN_ARG_INDEX:
                args = call.child_by_field_name('arguments')
                arg_nodes = [c for c in args.children if c.is_named] if args else []
                if arg_nodes:
                    out['obj_vars'].append(_root_var(_node_text(arg_nodes[0])))
                idx = LEN_ARG_INDEX[callee]
                if len(arg_nodes) > idx:
                    out['len_vars'].append(_root_var(_node_text(arg_nodes[idx])))
        for sub in subscripts:
            value = sub.child_by_field_name('value')
            index = sub.child_by_field_name('index')
            if value is not None:
                out['obj_vars'].append(_root_var(_node_text(value)))
            if index is not None:
                out['len_vars'].append(_root_var(_node_text(index)))
    elif family == 'integer':
        for n in _walk(root):
            if n.type == 'binary_expression':
                left = n.child_by_field_name('left')
                right = n.child_by_field_name('right')
                if left is None or right is None:
                    continue
                op_text = n.text[
                    left.end_byte - n.start_byte: right.start_byte - n.start_byte
                ].decode('utf8', errors='ignore').strip()
                if op_text in ARITH_OPS:
                    for child in (left, right):
                        out['vars'].append(_root_var(_node_text(child)))
            elif n.type in ('update_expression', 'unary_expression'):
                out['vars'].append(_root_var(_node_text(n)))
    elif family == 'null':
        for n in _walk(root):
            if n.type == 'field_expression':
                obj = n.child_by_field_name('argument')
                if obj is not None:
                    out['vars'].append(_root_var(_node_text(obj)))
                    break
            if n.type == 'unary_expression':
                named = [c for c in n.children if c.is_named]
                if named:
                    out['vars'].append(_root_var(_node_text(named[0])))
                    break
            if n.type == 'subscript_expression':
                value = n.child_by_field_name('value')
                if value is not None:
                    out['vars'].append(_root_var(_node_text(value)))
                    break
    elif family == 'lifetime':
        obj = str(sink.get('object_id') or sink.get('abstract_object') or '')
        if obj:
            out['obj_vars'].append(_root_var(obj))
        out['vars'] = list(out['obj_vars'])

    for key in out:
        out[key] = list(dict.fromkeys(v for v in out[key] if v))
    if not out['vars']:
        out['vars'] = list(dict.fromkeys(out['len_vars'] + out['obj_vars']))
    return out


def classify_family(sink: dict) -> str:
    category = str(sink.get('category') or sink.get('sink_category') or '')
    if category in LIFETIME_CATEGORIES:
        return 'lifetime'
    if category in INTEGER_CATEGORIES:
        return 'integer'
    if category == 'Potential NULL Dereference':
        return 'null'
    if category in BOUNDS_CATEGORIES:
        return 'bounds'
    operation = str(sink.get('operation') or '')
    callee_match = re.search(r'\b([A-Za-z_]\w*)\s*\(', operation)
    if callee_match and callee_match.group(1) in LEN_ARG_INDEX:
        return 'bounds'
    if category == 'Dereference':
        notes = ' '.join(str(x) for x in _safe_list(sink.get('static_notes')))
        if notes:
            return 'null'
    return ''


# ---------------------------------------------------------------------------
# Family retrieval
# ---------------------------------------------------------------------------

def guards_mentioning(scan: dict, vars_: list, before_byte: int) -> list:
    out = []
    for cond in scan['conditions']:
        if before_byte >= 0 and cond['cond_byte'] >= before_byte:
            continue
        shared = [v for v in vars_ if v in cond['vars']]
        if shared:
            out.append({**cond, 'matched_vars': shared, 'scope': 'UNKNOWN'})
    return out


def retrieve_counterevidence(sink: dict, family: str, scan: dict) -> dict:
    """Run family retrieval for a single sink, returning raw retrieval results (no new/old information judgement)."""
    key = sink_key_vars(sink, family)
    sink_byte = _safe_int(sink.get('start_byte'), -1)
    found = {'guards': [], 'capacities': [], 'helpers': [], 'clamps': [],
             'refresh_events': [], 'object_writes': []}

    if family == 'null':
        found['guards'] = guards_mentioning(scan, key['vars'], sink_byte)
        for event in _safe_list(sink.get('event_sequence')):
            if event.get('kind') == 'assign':
                found['refresh_events'].append(event)
    elif family == 'integer':
        found['guards'] = guards_mentioning(scan, key['vars'], sink_byte)
        # a helper must align with the sink's operand entities, otherwise it is an unrelated fact, not evidence
        key_vars = set(key['vars'])
        found['helpers'] = [
            h for h in scan['helpers']
            if (sink_byte < 0 or h['byte'] < sink_byte)
            and key_vars & set(h.get('vars') or [])
        ]
    elif family == 'bounds':
        found['guards'] = guards_mentioning(
            scan, key['len_vars'] or key['vars'], sink_byte)
        obj_vars = key['obj_vars'] or key['vars']
        found['capacities'] = [c for c in scan['capacities']
                               if c['var'] in obj_vars]
        len_vars = set(key['len_vars'])
        found['clamps'] = [c for c in scan['clamps']
                           if len_vars & set(c['vars'])]
    elif family == 'lifetime':
        for event in _safe_list(sink.get('event_sequence')):
            if str(event.get('kind') or '') in ('assign', 'free'):
                found['refresh_events'].append(event)
        # Function-wide writes to the tracked variable/field: candidate refresh,
        # field-clear or replacement evidence. The tracked names come from the
        # observation's own event texts (capture assignments and field paths),
        # never from name guessing. The verifier gets concrete sites to check
        # instead of having to invent or assume a refresh.
        tracked: set = set()
        # The abstract object id names the tracked entity directly
        # (variable::srp->rq->cmd / field::rdev->ena_pin / macro::CUR_PTR);
        # include its field-path prefixes so a clear of an ancestor handle
        # (e.g. `srp->rq = NULL`) is retrieved as well.
        obj_text = str(sink.get('object_id') or sink.get('abstract_object') or '')
        obj_text = re.sub(r'^(variable|field|macro|allocation)::', '', obj_text)
        obj_text = re.sub(r'::.*$', '', obj_text)
        obj_match = re.match(
            r'[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*', obj_text,
        )
        if obj_match:
            parts = re.split(r'\s*(?:->|\.)\s*', obj_match.group(0))
            for cut in range(1, len(parts) + 1):
                tracked.add('->'.join(parts[:cut]))
        for event in _safe_list(sink.get('event_sequence')):
            text = str(event.get('text') or event.get('code') or '')
            if not text:
                continue
            assign = re.match(
                r'\s*\*?\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*=[^=]',
                text,
            )
            if assign:
                tracked.add(re.sub(r'\s+', '', assign.group(1)))
            for path_match in re.finditer(
                r'[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+', text,
            ):
                tracked.add(re.sub(r'\s+', '', path_match.group(0)))
        for write in scan.get('writes') or []:
            lhs = str(write.get('lhs') or '')
            if not lhs:
                continue
            # Only real rebinding sites count as refresh/clear/replacement: a
            # call argument is a use, not a write; the sink's own site is not
            # evidence about itself.
            if write.get('kind') not in ('assign', 'update', 'decl'):
                continue
            if sink_byte >= 0 and write.get('byte') == sink_byte:
                continue
            # Full-lhs match only: falling back to the root variable would pull
            # in writes to unrelated sibling fields (sfp->cmd_q for a
            # sfp->reserve.pages object). For plain identifiers also accept
            # subscript/deref write forms (`end[i] =`, `*p =`).
            if lhs in tracked or any(
                isinstance(name, str) and '->' not in name and '.' not in name
                and (lhs.startswith(name + '[') or lhs == '*' + name)
                for name in tracked
            ):
                found['object_writes'].append({
                    **write,
                    'after_sink': sink_byte >= 0 and write['byte'] > sink_byte,
                })
        if tracked and not found['object_writes']:
            # A positive absence statement: the function-wide scan found no write
            # to any tracked entity, so no refresh/clear/replacement site exists
            # inside this function. Scope-limited to the scanned function.
            found['no_write_found'] = sorted(tracked)

    return {'family': family, 'key_vars': key, **found}


def select_new_items(retrieval: dict, task_guard_texts: set,
                     task_code_texts: set) -> dict:
    """Filter out items already present in the prompt text pools, keeping only new information."""
    guards = [g for g in retrieval.get('guards', [])
              if _norm_text(g['raw']) not in task_guard_texts]
    events = [e for e in retrieval.get('refresh_events', [])
              if _norm_text(str(e.get('text') or e.get('code') or '')) not in task_code_texts]
    caps = [c for c in retrieval.get('capacities', [])
            if not any(c['var'] in code and c['size_text'] and c['size_text'] in code
                       for code in task_code_texts)]
    helpers = [h for h in retrieval.get('helpers', [])
               if not any(h['callee'] in code for code in task_code_texts)]
    clamps = [c for c in retrieval.get('clamps', [])
              if not any(c['callee'] in code for code in task_code_texts)]
    # object_writes are not filtered against the text pools: lhs substring matching is too coarse and over-kills (e.g. 'end' is
    # a substring of many code texts), and the framing semantics of "candidate refresh/clear" is itself new information;
    # dedup by (lhs, byte) only. no_write_found is a scan-completeness statement and is likewise kept.
    seen_writes = set()
    object_writes = []
    for w in retrieval.get('object_writes', []):
        marker = (str(w.get('lhs') or ''), w.get('byte'))
        if marker in seen_writes:
            continue
        seen_writes.add(marker)
        object_writes.append(w)
    return {'family': retrieval.get('family'), 'key_vars': retrieval.get('key_vars'),
            'guards': guards, 'refresh_events': events, 'capacities': caps,
            'helpers': helpers, 'clamps': clamps, 'object_writes': object_writes,
            'no_write_found': retrieval.get('no_write_found') or []}


def applicable_families(sink: dict) -> list:
    """Return the evidence families applicable to this sink (primary classification + conservative secondary family).

    Motivation: the stage-1 hypothesis's mechanism family may differ from the sink's static primary classification (e.g. memcpy classed as
    bounds while the actual root-cause hypothesis is integer overflow). The secondary family currently only adds integer —
    when the operation text contains arithmetic/update expressions, integer evidence (operand guards, entity-aligned
    checked helpers) is equally relevant to integer-family hypotheses."""
    primary = classify_family(sink)
    # lifetime retrieval only serves observation-level sinks (suspect chains with incomplete evidence); for completed candidates
    # the event sequence is already fully rendered into the prompt, so extra contextual write sites would only repeat and amplify.
    if primary == 'lifetime' and not (
        sink.get('evidence_status')
        or str(sink.get('category') or sink.get('sink_category') or '') == 'lifecycle_suspect'
    ):
        primary = ''
    out = [primary] if primary else []
    if 'integer' not in out:
        try:
            if sink_key_vars(sink, 'integer')['vars']:
                out.append('integer')
        except Exception:
            pass
    return out


def render_grouped_items(retrieval: dict, max_items: int = 8) -> dict:
    """Render grouped by evidence role (without prejudging semantic roles):
    candidate_defensive: candidate defensive evidence (must prove dominance/path compatibility itself before acting as a blocker);
    unresolved_state_updates: prior state updates on the same object (may support or refute)."""
    defensive = []
    for guard in retrieval.get('guards', []):
        defensive.append(
            f"guard `{guard['raw']}` constrains {guard['matched_vars']} "
            f"before this operation (branch scope UNKNOWN - verify dominance yourself)"
        )
    for cap in retrieval.get('capacities', []):
        defensive.append(
            f"capacity `{cap['var']} = {cap['callee']}({cap['size_text']})` "
            f"defines an allocation extent for the accessed object"
        )
    for helper in retrieval.get('helpers', []):
        defensive.append(
            f"checked helper `{helper['callee']}(...)` present before this "
            f"operation (entity-aligned on {helper.get('vars') or []})"
        )
    for clamp in retrieval.get('clamps', []):
        defensive.append(
            f"clamp `{clamp['callee']}({', '.join(clamp['args_text'])})` bounds "
            f"{clamp['vars']} before this operation"
        )
    updates = []
    for event in retrieval.get('refresh_events', []):
        text = str(event.get('text') or event.get('code') or '')
        if text:
            updates.append(
                f"event `{text}` ({event.get('kind', 'event')}, line "
                f"{event.get('line', '?')}) touches the same object before this operation"
            )
    writes_by_lhs: dict = {}
    for write in retrieval.get('object_writes', []):
        entry = writes_by_lhs.setdefault(
            str(write.get('lhs') or ''), {'before': [], 'after': []})
        entry['after' if write.get('after_sink') else 'before'].append(write.get('byte'))
    for lhs, counts in writes_by_lhs.items():
        sites = []
        if counts['before']:
            sites.append(f"{len(counts['before'])} before at bytes {counts['before']}")
        if counts['after']:
            sites.append(f"{len(counts['after'])} after at bytes {counts['after']}")
        updates.append(
            f"write(s) to `{lhs}` ({'; '.join(sites)} relative to this operation) — "
            f"candidate refresh/clear/replacement; verify order and branch dominance yourself"
        )
    for name in retrieval.get('no_write_found') or []:
        updates.append(
            f"function-wide scan found NO write to `{name}` — no refresh/clear/"
            f"replacement site for it exists inside the scanned function"
        )
    defensive = list(dict.fromkeys(defensive))
    updates = list(dict.fromkeys(updates))
    groups = {}
    if defensive:
        groups['candidate_defensive'] = defensive[:max_items]
    if updates:
        groups['unresolved_state_updates'] = updates[:max(1, max_items // 2)]
    return groups


def render_counterevidence_items(retrieval: dict, max_items: int = 8) -> list:
    """Render retrieval results as compact prompt lines (scope/heuristic level annotated truthfully)."""
    items = []
    for guard in retrieval.get('guards', []):
        items.append(
            f"guard `{guard['raw']}` constrains {guard['matched_vars']} "
            f"before this operation (branch scope UNKNOWN - verify dominance yourself)"
        )
    for event in retrieval.get('refresh_events', []):
        text = str(event.get('text') or event.get('code') or '')
        if text:
            items.append(
                f"event `{text}` ({event.get('kind', 'event')}, line "
                f"{event.get('line', '?')}) touches the same object before this operation"
            )
    for cap in retrieval.get('capacities', []):
        items.append(
            f"capacity `{cap['var']} = {cap['callee']}({cap['size_text']})` "
            f"defines an allocation extent for the accessed object"
        )
    for helper in retrieval.get('helpers', []):
        items.append(f"checked helper `{helper['callee']}(...)` present before this operation")
    for clamp in retrieval.get('clamps', []):
        items.append(
            f"clamp `{clamp['callee']}({', '.join(clamp['args_text'])})` bounds "
            f"{clamp['vars']} before this operation"
        )
    deduped = list(dict.fromkeys(items))
    return deduped[:max_items]


# ---------------------------------------------------------------------------
# null-family supporting signal: producer call results NULL-tested elsewhere in the file
# ---------------------------------------------------------------------------
#
# Motivation: CWE-476-style hypotheses are often over-rejected because "the producer cannot be proven to return NULL", while
# other functions in the same file often NULL-test the same producer (e.g. skb_dst(skb)) — exactly the
# supporting evidence the verifier checklist calls "the codebase treats this pointer as nullable". This signal is only
# rendered as supporting evidence (explicitly marked NOT a blocker) and takes no part in any filtering/dedup logic.

def sink_producer_calls(sink: dict) -> list:
    """Extract from the sink operation text the "call expressions whose result is dereferenced".
    Returns [{'callee': str, 'call_text': str}]; e.g. skb_dst(skb)->dev yields
    {'callee': 'skb_dst', 'call_text': 'skb_dst(skb)'}. At most 2."""
    operation = str(sink.get('operation') or '')
    root = _parse_op(operation)
    if root is None:
        return []
    producers = []
    for node in _walk(root):
        target = None
        if node.type == 'field_expression':
            target = node.child_by_field_name('argument')
        elif node.type == 'subscript_expression':
            target = node.child_by_field_name('value')
        elif node.type == 'pointer_expression':
            named = [c for c in node.children if c.is_named]
            target = named[0] if named else None
        if target is None:
            continue
        for sub in _walk(target):
            if sub.type != 'call_expression':
                continue
            fn = sub.child_by_field_name('function')
            callee = _node_text(fn) if fn else ''
            # only accept simple-identifier callees (skip indirect calls like p->f(...))
            if not callee or not re.fullmatch(r'[A-Za-z_]\w*', callee):
                continue
            producers.append({'callee': callee, 'call_text': _node_text(sub)})
            break  # one outermost producer per dereference point is enough
    deduped = []
    seen = set()
    for item in producers:
        if item['callee'] in seen:
            continue
        seen.add(item['callee'])
        deduped.append(item)
    return deduped[:2]


_NULL_TEST_RE_CACHE: dict = {}


def _is_null_test(raw: str, callee: str) -> bool:
    """Decide whether a condition text is a NULL test of callee(...)'s return value.
    Accepts: direct tests (if (f(x)) / f(x) ? :), !f(x), comparisons with NULL,
    and likely/unlikely-wrapped forms of the above. Rejects numeric comparisons like f(x) > 5."""
    text = (raw or '').strip()
    if not text or f'{callee}(' not in text:
        return False
    key = callee
    if key not in _NULL_TEST_RE_CACHE:
        esc = re.escape(callee)
        _NULL_TEST_RE_CACHE[key] = {
            'null_cmp': re.compile(
                rf'\b{esc}\s*\([^;]*?\)\s*(?:==|!=)\s*NULL\b'
                rf'|\bNULL\s*(?:==|!=)\s*{esc}\s*\('),
            'neg': re.compile(rf'!\s*(?:\(\s*)*{esc}\s*\('),
        }
    res = _NULL_TEST_RE_CACHE[key]
    if res['null_cmp'].search(text) or res['neg'].search(text):
        return True
    # a bare call, or a likely/unlikely-wrapped bare call, as the entire condition
    stripped = text
    for wrapper in ('likely', 'unlikely'):
        m = re.fullmatch(rf'{wrapper}\s*\((.*)\)', stripped, flags=re.S)
        if m:
            stripped = m.group(1).strip()
    stripped = stripped.strip('() ')
    return stripped.startswith(f'{callee}(') and not re.search(
        r'[<>=!&|+\-*/%]\s*[^)]*$', stripped[len(callee):].rstrip(') '))


def find_producer_null_checks(scans: dict, callee: str, exclude_func: str,
                              max_sites: int = 2) -> list:
    """Find NULL-test uses of the producer in file-level scan results ({func_name: scan}).
    Skips the sink's own function (same-function NULL tests already enter the regular guard retrieval).
    Returns [{'func': str, 'raw': str}]."""
    sites = []
    for func_name, scan in scans.items():
        if func_name == exclude_func:
            continue
        pools = list(scan.get('conditions', [])) + \
            list(scan.get('ternary_conditions', []))
        for cond in pools:
            raw = _norm_text(cond.get('raw'))
            if _is_null_test(raw, callee):
                sites.append({'func': func_name, 'raw': raw})
                break  # one representative per function is enough
        if len(sites) >= max_sites:
            break
    return sites
