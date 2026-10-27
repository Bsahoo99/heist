"""Deterministic traces, used when the model fails twice. Built only from the finding and graph.

Every step points at a real graph node and, when the node has code, at a real file and line
taken from the finding's refs or the node's own ref. With a workspace, fix diffs quote the
real lines around the change; without one they fall back to insert-only hunks.
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass

from heist.fetch import Workspace
from heist.models import (
    AppGraph,
    CodeRef,
    Finding,
    FixOut,
    Node,
    Stack,
    StepOut,
    TraceOut,
    scrub_dashes,
)

log = logging.getLogger(__name__)

REDACTED = "<redacted>"
OWNER_COLUMNS = ("user_id", "owner_id", "owner", "sender_id", "author_id", "created_by")
PROFILE_TABLES = {"profiles", "profile", "users", "accounts"}
_LITERAL_RE = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\])*)\1""")
_DENO_HANDLER_RE = re.compile(r"(?:Deno\.serve|\bserve)\(\s*(?:async\s*)?\(?\s*(\w+)?")
_EXPORT_HANDLER_RE = re.compile(
    r"export\s+(?:default\s+)?(?:async\s+)?function\s*\w*\s*\(\s*(\w+)?"
)
_FROM_RE = re.compile(r"""\.from\(\s*['"`]([^'"`]+)['"`]\s*\)""")
_EQ_RE = re.compile(r"\.eq\([^()]*(?:\([^()]*\)[^()]*)*\)")


VENDORS = {
    "api.openai.com": "OpenAI",
    "api.anthropic.com": "Anthropic",
    "generativelanguage.googleapis.com": "Google AI",
    "api.replicate.com": "Replicate",
    "api.meta.ai": "Meta AI",
}


def _vendor(host: str) -> str:
    return VENDORS.get(host, host or "the paid API")


_VAR_NOISE = {"vite", "next", "public", "key", "api", "secret", "token", "the"}


def hosts_for_var(var: str, g: AppGraph) -> list[Node]:
    """External API nodes whose host matches a secret's name, e.g. VITE_OPENAI_API_KEY."""
    tokens = [t for t in re.split(r"[_\s]+", var.lower()) if len(t) > 2 and t not in _VAR_NOISE]
    return [n for n in g.nodes if n.kind == "external_api" and any(t in n.name for t in tokens)]


def builder_tool(stack: Stack) -> str:
    return "Lovable" if stack == "vite_supabase" else "Cursor or v0"


# --- small helpers ----------------------------------------------------------------------


@dataclass
class _Ctx:
    f: Finding
    g: AppGraph
    ws: Workspace | None
    nodes: dict[str, Node]

    def node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def lines(self, rel: str) -> list[str] | None:
        if self.ws is None or rel not in self.ws.files:
            return None
        try:
            text = (self.ws.app_root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        return text.splitlines()

    @property
    def tool(self) -> str:
        return builder_tool(self.g.stack)

    def ev(self, key: str, default: str) -> str:
        value = self.f.evidence.get(key)
        return str(value) if value else default


def _step(
    node: Node, file: str | None, line: int | None, data: str, story: str, why: str, code: str
) -> StepOut:
    return StepOut(
        node_id=node.id,
        zone=node.zone,
        file=file,
        line=line,
        data=data,
        story=story,
        why=why,
        code=code,
    )


def _at(node: Node, data: str, story: str, why: str, code: str) -> StepOut:
    """A step located at the node's own code, or with no location if it has none."""
    ref = node.ref
    return _step(
        node, ref.file if ref else None, ref.start_line if ref else None, data, story, why, code
    )


def _at_ref(node: Node, ref: CodeRef, data: str, story: str, why: str, code: str) -> StepOut:
    return _step(node, ref.file, ref.start_line, data, story, why, code)


def _node_for_ref(ctx: _Ctx, ref: CodeRef) -> Node:
    """The most specific graph node for a code location."""
    own = [n for i in ctx.f.node_ids if (n := ctx.node(i)) is not None]
    same_file = [n for n in own if n.ref is not None and n.ref.file == ref.file]
    if same_file:
        return same_file[0]
    covering = [
        n
        for n in ctx.g.nodes
        if n.ref is not None
        and n.ref.file == ref.file
        and n.ref.start_line <= ref.start_line <= n.ref.end_line
    ]
    if covering:
        return min(covering, key=lambda n: n.ref.end_line - n.ref.start_line if n.ref else 0)
    in_file = [n for n in ctx.g.nodes if n.ref is not None and n.ref.file == ref.file]
    if in_file:
        return in_file[0]
    if own:
        return own[0]
    return _front(ctx, [], any_page=True) or ctx.nodes["visitor"]


def _front(ctx: _Ctx, targets: list[str], *, any_page: bool = False) -> Node | None:
    """The page (or exact client call) that reaches one of the targets, else any page if asked."""
    for e in ctx.g.edges:
        if e.dst not in targets or not e.src.startswith("page:"):
            continue
        page = ctx.node(e.src)
        if page is None or page.ref is None:
            continue
        target = ctx.node(e.dst)
        wanted = f"'{target.name}'" if target else None
        for n in ctx.g.nodes:
            in_page = n.kind == "client_call" and n.id.startswith(f"client:{page.ref.file}:")
            if in_page and wanted and wanted in n.name:
                return n
        return page
    if not any_page:
        return None
    pages = sorted((n for n in ctx.g.nodes if n.kind == "page"), key=lambda n: n.id)
    return pages[0] if pages else None


def _downstream(ctx: _Ctx, node_id: str, limit: int = 2) -> list[Node]:
    out: list[Node] = []
    for e in ctx.g.edges:
        if e.src == node_id and (n := ctx.node(e.dst)) is not None and n not in out:
            out.append(n)
    return out[:limit]


def _visitor(ctx: _Ctx, story: str, data: str = "nothing but a web browser") -> StepOut:
    return _at(
        ctx.nodes["visitor"],
        data,
        story,
        "Every request starts here. The app cannot trust anything the visitor sends.",
        "No code runs yet. The visitor only has what the public website gives them.",
    )


def _desk(ctx: _Ctx, story: str, why: str, code: str, data: str) -> StepOut:
    return _at(ctx.nodes["auth:supabase"], data, story, why, code)


def _hide_literals(line: str) -> str:
    return _LITERAL_RE.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(1)}", line)


def _indent(line: str | None, default: str = "  ") -> str:
    if not line:
        return default
    return line[: len(line) - len(line.lstrip())] or default


# --- diffs ------------------------------------------------------------------------------

# An edit is (old start line, removed lines, added lines). With no removed lines, the start is
# the line the new lines go after (0 for the top of the file).
_Edit = tuple[int, list[str], list[str]]


def _file_diff(path: str, edits: list[_Edit]) -> str:
    out = [f"--- a/{path}", f"+++ b/{path}"]
    offset = 0
    for start, removed, added in sorted(edits, key=lambda e: e[0]):
        if removed:
            # A pure deletion names the line before it in the new file.
            new_start = start + offset - (0 if added else 1)
            out.append(f"@@ -{start},{len(removed)} +{new_start},{len(added)} @@")
        else:
            new_start = start + offset + 1
            out.append(f"@@ -{start},0 +{new_start},{len(added)} @@")
        out += [f"-{x}" for x in removed] + [f"+{x}" for x in added]
        offset += len(added) - len(removed)
    return "\n".join(out)


def _new_file_diff(path: str, lines: list[str]) -> str:
    head = ["--- /dev/null", f"+++ b/{path}", f"@@ -0,0 +1,{len(lines)} @@"]
    return "\n".join(head + [f"+{x}" for x in lines])


def _next_migration(ctx: _Ctx, slug: str) -> str:
    files = sorted(ctx.g.db.migration_files) if ctx.g.db else []
    number = "0001"
    if files:
        base = files[-1].rsplit("/", 1)[-1]
        m = re.match(r"^(\d+)", base)
        if m:
            number = str(int(m.group(1)) + 1).zfill(len(m.group(1)))
    return f"supabase/migrations/{number}_{slug}.sql"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "x"


# --- auth snippets for side doors -------------------------------------------------------


def _is_edge_function(rel: str) -> bool:
    return rel.startswith("supabase/functions/")


def _handler(ctx: _Ctx, ref: CodeRef) -> tuple[int, str]:
    """(line to insert the sign-in check after, request variable name)."""
    lines = ctx.lines(ref.file)
    pattern = _DENO_HANDLER_RE if _is_edge_function(ref.file) else _EXPORT_HANDLER_RE
    if lines:
        for i, text in enumerate(lines, start=1):
            m = pattern.search(text)
            if m and text.rstrip().endswith("{"):
                return i, m.group(1) or "req"
    return ref.start_line, "req"


def _auth_lines(rel: str, req: str, indent: str, *, action: bool = False) -> list[str]:
    i = indent
    if _is_edge_function(rel):
        return [
            f"{i}const authClient = createClient(",
            f"{i}  Deno.env.get('SUPABASE_URL')!,",
            f"{i}  Deno.env.get('SUPABASE_ANON_KEY')!,",
            f"{i}  {{ global: {{ headers: {{ Authorization: {req}.headers.get('Authorization') ?? '' }} }} }},",
            f"{i})",
            f"{i}const {{ data: {{ user }} }} = await authClient.auth.getUser()",
            f"{i}if (!user) return new Response('Unauthorized', {{ status: 401 }})",
        ]
    deny = (
        "throw new Error('Unauthorized')"
        if action
        else "return Response.json({ error: 'Unauthorized' }, { status: 401 })"
    )
    return [
        f"{i}const authClient = await createClient()",
        f"{i}const {{ data: {{ user }} }} = await authClient.auth.getUser()",
        f"{i}if (!user) {deny}",
    ]


def _import_edits(ctx: _Ctx, rel: str) -> list[_Edit]:
    lines = ctx.lines(rel)
    if lines is not None and any("createClient" in x for x in lines):
        return []
    if _is_edge_function(rel):
        return [(0, [], ["import { createClient } from 'npm:@supabase/supabase-js@2'"])]
    return [(0, [], ["import { createClient } from '@/utils/supabase/server'"])]


def _owner_column(ctx: _Ctx, table: str) -> str | None:
    t = ctx.g.db.tables.get(table) if ctx.g.db else None
    if t is None:
        return None
    names = [c.name for c in t.columns]
    for c in OWNER_COLUMNS:
        if c in names:
            return c
    if table in PROFILE_TABLES and "id" in names:
        return "id"
    return None


# --- mistake 1: secret key in the front end ---------------------------------------------


def _m1(ctx: _Ctx) -> TraceOut:
    f = ctx.f
    var = ctx.ev("var", "the secret key")
    ref = f.refs[0] if f.refs else None
    where = _node_for_ref(ctx, ref) if ref else None
    page = _front(ctx, [], any_page=True)
    ext = next(iter(hosts_for_var(var, ctx.g)), None)
    shop_why = "The front end is shipped to every visitor's browser, so everything in it is public."

    ghost = [_visitor(ctx, "A customer walks up to the shop.")]
    if page:
        ghost.append(
            _at(
                page,
                "the page and its public settings",
                "They look through the shop window. Only things meant for customers are on display.",
                shop_why,
                f"{page.name} runs in the browser and can only use values that are safe to show.",
            )
        )
    if ext:
        ghost.append(
            _at(
                ext,
                "requests sent from the back room",
                "Calls to the outside supplier should be made from the back room, where the key never leaves the building.",
                f"{ext.name} trusts whoever holds the key, so only the server should hold it.",
                "A server-side function adds the key to the request, so the browser never sees it.",
            )
        )
    if len(ghost) < 2:
        ghost.append(
            _desk(
                ctx,
                "They check in at the guard desk like everyone else.",
                "Supabase Auth decides who the visitor is.",
                "No secret is needed to sign in.",
                "an email and a password",
            )
        )

    attack = [_visitor(ctx, "Someone with bad intentions walks up to the same shop.")]
    if page and page is not where:
        attack.append(
            _at(
                page,
                "the full front-end bundle",
                "They do not even go inside. They read everything taped to the shop window.",
                shop_why,
                f"{page.name} is bundled with every VITE_ or NEXT_PUBLIC_ value the build can see.",
            )
        )
    if where and ref:
        attack.append(
            _at_ref(
                where,
                ref,
                f"{var}, in plain text",
                f"There it is: the key under the doormat. {var} is written right where anyone can pick it up.",
                "A key that pays for or controls an outside service must stay on the server. Once it is in the browser, it belongs to everyone.",
                f"{ref.file} line {ref.start_line} defines {var}. Build tools copy public-prefixed values into the JavaScript every visitor downloads.",
            )
        )
    if ext:
        attack.append(
            _at(
                ext,
                f"requests signed with {var}",
                "They walk across the road to the supplier and order on your account.",
                f"{ext.name} cannot tell your app from the attacker: both send the same key.",
                "Any request with this key is billed to and trusted as your account.",
            )
        )
    if len(attack) < 3:
        attack.append(
            _desk(
                ctx,
                "They never needed to sign in at the guard desk.",
                "Signing in protects user data, not keys that are already public.",
                "Supabase Auth is not involved: the key works on its own.",
                "no account at all",
            )
        )

    server_var = re.sub(r"^(VITE_|NEXT_PUBLIC_)", "", var) if var != "the secret key" else "API_KEY"
    diff = _secret_diff(ctx, ref, var)
    return TraceOut(
        ghost_path=ghost,
        attack_path=attack,
        fix=FixOut(
            explanation=(
                f"{var} is bundled into the website, so every visitor can copy it. Move the code "
                "that uses it into a Supabase Edge Function, store the key there as the secret "
                f"{server_var} (without the public prefix), and call that function from the page. "
                "Then rotate the key in the provider's dashboard, because the old one has already "
                "been public."
            ),
            diff=diff,
            prompt=(
                f"{ctx.tool}, please move {var} out of the front end. Create a Supabase Edge "
                f"Function that reads the key from a secret called {server_var} and makes the "
                "outside API call, have the page call that function instead, and remove the "
                f"key from {ref.file if ref else 'the front-end code'}. I will rotate the old key."
            ),
        ),
    )


def _secret_diff(ctx: _Ctx, ref: CodeRef | None, var: str, replacement: str | None = None) -> str:
    if ref is None:
        return _new_file_diff("SECURITY.md", [f"Keep {var} on the server only."])
    lines = ctx.lines(ref.file)
    name = ref.file.rsplit("/", 1)[-1]
    if name == ".env" or name.startswith(".env."):
        real = lines[ref.start_line - 1] if lines and ref.start_line <= len(lines) else ""
        key = real.split("=", 1)[0].strip() if "=" in real else var
        old = [f"{key}={REDACTED}"]
        return _file_diff(
            ref.file, [(ref.start_line, old, [] if replacement is None else [replacement])]
        )
    old_line = lines[ref.start_line - 1] if lines and ref.start_line <= len(lines) else None
    if old_line is None:
        return _file_diff(
            ref.file, [(ref.start_line - 1, [], [f"// TODO: remove {var} from the front end"])]
        )
    new = (
        replacement
        if replacement is not None
        else f"{_indent(old_line, '')}// {var} removed: call the Edge Function instead"
    )
    return _file_diff(ref.file, [(ref.start_line, [_hide_literals(old_line)], [new])])


# --- mistake 2: service role key in the front end ---------------------------------------


def _vault_targets(ctx: _Ctx, limit: int = 2) -> list[Node]:
    tables = [n for n in ctx.g.nodes if n.kind == "table"]
    personal = [n for n in tables if _owner_column(ctx, n.name)]
    return (personal or tables)[:limit]


def _m2(ctx: _Ctx) -> TraceOut:
    f = ctx.f
    var = ctx.ev("var", "SUPABASE_SERVICE_ROLE_KEY")
    ref = f.refs[0] if f.refs else None
    where = _node_for_ref(ctx, ref) if ref else None
    tables = _vault_targets(ctx)
    page = _front(ctx, [t.id for t in tables], any_page=True)

    ghost = [_visitor(ctx, "A customer walks up to the shop.")]
    if page:
        ghost.append(
            _at(
                page,
                "the public anon key",
                "Through the shop window they get a visitor badge that opens nothing by itself.",
                "The anon key is safe to share because the vault's locks still apply to it.",
                f"{page.name} talks to Supabase with the anon key and the user's session.",
            )
        )
    ghost.append(
        _desk(
            ctx,
            "They show their ID at the guard desk and get a pass with their name on it.",
            "Supabase Auth ties every request to one user, so the locks know whose box to open.",
            "auth.uid() is set from the signed-in user's token.",
            "the user's own session",
        )
    )
    if tables:
        t = tables[0]
        ghost.append(
            _at(
                t,
                f"only this user's rows in {t.name}",
                f"At the vault, their pass opens their own box in {t.name} and nothing else.",
                "Row level security checks every row against the user on the pass.",
                f"Policies on {t.name} filter rows by auth.uid().",
            )
        )

    attack = [_visitor(ctx, "Someone with bad intentions walks up to the same shop.")]
    if where and ref:
        attack.append(
            _at_ref(
                where,
                ref,
                f"{var}, the master key",
                "Taped to the shop window is the master key to the whole building.",
                "The service role key skips every lock in the database. It must never leave the server.",
                f"{ref.file} line {ref.start_line} puts {var} into front-end code, so the build ships it to every browser.",
            )
        )
    attack.append(
        _desk(
            ctx,
            "With the master key they walk straight past the guard desk.",
            "The guard desk only matters for normal passes. The service role is not a user, so no one checks it.",
            "Requests made with the service role key bypass Supabase Auth and row level security.",
            "the service role key instead of a user session",
        )
    )
    for t in tables:
        attack.append(
            _at(
                t,
                f"every row in {t.name}",
                f"Every box in the vault opens, including {t.name}.",
                "Row level security is skipped entirely for the service role.",
                f"With the service role, reads and writes on {t.name} ignore every policy.",
            )
        )
    if len(attack) < 3:
        attack.append(
            _visitor(
                ctx, "They leave with whatever they wanted.", "everything the master key opens"
            )
        )

    replacement = None
    if ref is not None:
        lines = ctx.lines(ref.file)
        old = lines[ref.start_line - 1] if lines and ref.start_line <= len(lines) else None
        name = ref.file.rsplit("/", 1)[-1]
        if (
            old is not None
            and not (name == ".env" or name.startswith(".env."))
            and "SERVICE_ROLE" in old
        ):
            replacement = old.replace("SERVICE_ROLE_KEY", "ANON_KEY").replace(
                "SERVICE_ROLE", "ANON"
            )
    return TraceOut(
        ghost_path=ghost,
        attack_path=attack,
        fix=FixOut(
            explanation=(
                f"The Supabase service role key ({var}) is the master key: it ignores every "
                "database rule. Remove it from the front end and use the normal anon key there. "
                "Move anything that truly needs admin rights into an Edge Function, which can read "
                "the service role key from its own secrets. Then rotate the service role key in "
                "the Supabase dashboard (Project Settings, API), because the old one is public."
            ),
            diff=_secret_diff(ctx, ref, var, replacement),
            prompt=(
                f"{ctx.tool}, please remove the Supabase service role key ({var}) from all "
                "front-end code and use the anon key instead. If something needs admin access, "
                "move it into a Supabase Edge Function that checks the user is signed in. I will "
                "rotate the service role key in the Supabase dashboard."
            ),
        ),
    )


# --- mistake 3: tables anyone can read --------------------------------------------------


def _m3(ctx: _Ctx) -> TraceOut:
    f = ctx.f
    table = ctx.ev("table", "")
    t_node = ctx.node(f"table:{table}") or next(
        (n for i in f.node_ids if (n := ctx.node(i)) and n.kind == "table"), None
    )
    if t_node is None:
        return _m0(ctx)
    table = t_node.name
    reason = ctx.ev("reason", "rls_off")
    policy = next((n for i in f.node_ids if (n := ctx.node(i)) and n.kind == "policy"), None)
    ref = f.refs[0] if f.refs else t_node.ref
    owner = _owner_column(ctx, table)
    page = _front(ctx, [t_node.id])
    schema = ctx.g.db.tables[table].schema if ctx.g.db and table in ctx.g.db.tables else "public"
    qualified = f"{schema}.{table}"

    ghost = [_visitor(ctx, "A customer walks up to the shop.")]
    if page:
        ghost.append(
            _at(
                page,
                f"a request for rows in {table}",
                "In the shop window, the page asks the vault for this customer's records.",
                "The browser can ask for anything, so the vault must decide what to hand over.",
                f"{page.name} queries {table} with the public anon key.",
            )
        )
    ghost.append(
        _desk(
            ctx,
            "They show their ID at the guard desk and get a pass with their name on it.",
            "Supabase Auth identifies the user, so the vault knows whose rows are whose.",
            "auth.uid() becomes the signed-in user's id for every query.",
            "the user's session",
        )
    )
    ghost.append(
        _at(
            t_node,
            f"only rows where {owner or 'the owner'} is this user",
            f"At the vault, the lock on {table} opens only their own box.",
            "Row level security turns every query into 'only my rows'.",
            f"A policy like auth.uid() = {owner or 'owner_column'} filters {table} row by row.",
        )
    )

    attack = [_visitor(ctx, "Someone with bad intentions walks up to the same shop.")]
    if page:
        attack.append(
            _at(
                page,
                "the public anon key and the table name",
                "The shop window shows them exactly which vault box the page uses.",
                "The anon key and table names are public by design. The lock is what keeps data safe.",
                f"{page.name} reveals that the app reads {table}.",
            )
        )
    if reason == "open_to_any_user":
        attack.append(
            _desk(
                ctx,
                "They sign up with any email. The guard desk gives a pass to anyone who asks.",
                "Being signed in proves who you are, not which rows are yours.",
                "Sign-up is open, so auth.uid() is not null for any account.",
                "a brand new account",
            )
        )
    else:
        attack.append(
            _desk(
                ctx,
                "They walk right past the guard desk. Nobody asks who they are.",
                "Signing in only helps if the vault checks the pass. Here it does not.",
                "The public anon key alone is enough, so Supabase Auth is never involved.",
                "the public anon key, no account",
            )
        )
    if policy and ref:
        attack.append(
            _at_ref(
                policy,
                ref,
                f"a lock that opens for {'any pass' if reason == 'open_to_any_user' else 'everyone'}",
                "Here is the broken lock: it checks that you have a pass, not that the box is yours."
                if reason == "open_to_any_user"
                else "Here is the broken lock: it opens for anyone at all.",
                "A read policy must compare the row's owner with the user. This one does not.",
                f"Policy {policy.name} on {table} lets every {'signed-in user' if reason == 'open_to_any_user' else 'visitor'} read every row.",
            )
        )
        attack.append(
            _at(
                t_node,
                f"every row in {table}",
                f"Every box in {table} swings open, not just their own.",
                "Without an owner check, one query returns everyone's records.",
                f"A plain select on {table} returns all rows.",
            )
        )
    else:
        loc = ref or t_node.ref
        assert loc is not None
        attack.append(
            _at_ref(
                t_node,
                loc,
                f"every row in {table}",
                f"The vault box {table} has no lock at all. They open it and take everything.",
                "Without row level security, the anon key can read and change every row.",
                f"{qualified} is created here and row level security is never enabled.",
            )
        )

    sql: list[str] = []
    if reason == "rls_off":
        sql += [f"alter table {qualified} enable row level security;", ""]
    elif policy:
        sql += [f'drop policy "{policy.name}" on {qualified};', ""]
    if owner:
        sql += [
            f'create policy "{_slug(table)}_select_own" on {qualified}',
            f"  for select to authenticated using ((select auth.uid()) = {owner});",
        ]
    else:
        sql += [
            "-- Add a policy that says who may read each row, for example:",
            f'-- create policy "{_slug(table)}_select_own" on {qualified}',
            "--   for select to authenticated using ((select auth.uid()) = user_id);",
        ]
    path = _next_migration(ctx, f"heist_lock_{_slug(table)}")
    public_ok = reason == "open_to_everyone" and f.severity == "low"
    what = {
        "rls_off": f"Row level security is off for {table}, so anyone with the public anon key can read every row.",
        "open_to_any_user": f"The read rule on {table} only checks that someone is signed in, so any account can read every row.",
    }.get(reason, f"The read rule on {table} lets anyone read every row.")
    how = (
        f"Add a new migration that turns the lock on and lets each user read only rows where {owner} is their own id."
        if owner
        else "Add a new migration that turns the lock on, then add a rule that says who may read each row."
    )
    if public_ok:
        how = (
            "If this table is meant to be public, nothing needs to change. If not, "
            + how[0].lower()
            + how[1:]
        )
    return TraceOut(
        ghost_path=ghost,
        attack_path=attack,
        fix=FixOut(
            explanation=f"{what} {how}",
            diff=_new_file_diff(path, sql),
            prompt=(
                f"{ctx.tool}, "
                + (
                    f"if the {table} table is not meant to be public, please "
                    if public_ok
                    else "please "
                )
                + f"lock down the {table} table in Supabase. Make sure row level security is "
                "enabled and replace any read policy that lets everyone or every signed-in user "
                "read all rows with one that only lets users read their own rows"
                f"{f' (where {owner} = auth.uid())' if owner else ''}. Add it as a new migration."
            ),
        ),
    )


# --- mistake 4: storage buckets ---------------------------------------------------------


def _m4(ctx: _Ctx) -> TraceOut:
    f = ctx.f
    bucket = ctx.ev("bucket", "")
    b_node = ctx.node(f"bucket:{bucket}") or next(
        (n for i in f.node_ids if (n := ctx.node(i)) and n.kind == "bucket"), None
    )
    if b_node is None:
        return _m0(ctx)
    bucket = b_node.name
    reason = ctx.ev("reason", "public_no_policy")
    ref = f.refs[0] if f.refs else b_node.ref
    assert ref is not None
    page = _front(ctx, [b_node.id])
    is_public = bool(f.evidence.get("public", reason != "private_no_policy"))

    ghost = [_visitor(ctx, "A customer walks up to the shop.")]
    if page:
        ghost.append(
            _at(
                page,
                "a file the user picked",
                "In the shop window, the customer hands over a file to store.",
                "The browser sends files straight to storage, so storage must check who sends them.",
                f"{page.name} uploads to the {bucket} bucket.",
            )
        )
    ghost.append(
        _desk(
            ctx,
            "They show their ID at the guard desk first.",
            "Storage rules use the signed-in user to decide who owns each file.",
            "auth.uid() is available to storage.objects policies.",
            "the user's session",
        )
    )
    ghost.append(
        _at(
            b_node,
            "only this user's folder",
            f"In the warehouse, they can reach only their own shelf in {bucket}.",
            "Per-user folders keep one customer's files away from another's.",
            f"A storage.objects policy limits {bucket} to the user's own folder.",
        )
    )

    attack = [_visitor(ctx, "Someone with bad intentions walks up to the same shop.")]
    if page:
        attack.append(
            _at(
                page,
                "the bucket name",
                "The shop window shows which warehouse the files go to.",
                "Bucket names are public. The rules on storage.objects are the real lock.",
                f"{page.name} names the {bucket} bucket in its upload call.",
            )
        )
    if is_public:
        attack.append(
            _at_ref(
                b_node,
                ref,
                "every file in the bucket",
                f"The {bucket} warehouse door is wide open. Anyone with a link can walk in and look.",
                "A public bucket serves files to anyone who has or guesses the URL, with no sign-in.",
                f"{ref.file} line {ref.start_line} creates {bucket} with public = true and no storage.objects policies.",
            )
        )
    else:
        attack.append(
            _at_ref(
                b_node,
                ref,
                "no access rules at all",
                f"The {bucket} warehouse has no rules posted. Right now nobody can use it, so the quick fix people reach for is propping the door open.",
                "Without storage.objects policies, the app cannot store files safely, and making the bucket public would expose every file.",
                f"{ref.file} line {ref.start_line} creates {bucket} as private with no storage.objects policies.",
            )
        )
    attack.append(
        _desk(
            ctx,
            "No guard checks who owns which shelf.",
            "Without policies, storage has no idea which file belongs to which user.",
            "No storage.objects policy mentions this bucket, so auth.uid() is never checked.",
            "no ownership check",
        )
    )

    lit = f"'{bucket}'"
    s = _slug(bucket)
    sql: list[str] = []
    if reason == "public_sensitive_no_policy":
        sql += [f"update storage.buckets set public = false where id = {lit};", ""]
    if reason == "public_no_policy":
        sql += [
            f'create policy "{s}_public_read" on storage.objects',
            f"  for select using (bucket_id = {lit});",
        ]
    else:
        sql += [
            f'create policy "{s}_read_own" on storage.objects',
            "  for select to authenticated",
            f"  using (bucket_id = {lit} and (select auth.uid())::text = (storage.foldername(name))[1]);",
        ]
    sql += [
        "",
        f'create policy "{s}_upload_own" on storage.objects',
        "  for insert to authenticated",
        f"  with check (bucket_id = {lit} and (select auth.uid())::text = (storage.foldername(name))[1]);",
    ]
    explanation = {
        "public_sensitive_no_policy": f"Files in {bucket} look private, but the bucket is public, so anyone with a link can open them. Make the bucket private and add rules so each user can only read and upload files in their own folder.",
        "private_no_policy": f"{bucket} is private but has no access rules, so the app cannot use it yet. Add rules that let each signed-in user read and upload only their own folder, instead of making the bucket public.",
    }.get(
        reason,
        f"{bucket} is public with no access rules. If these files are meant for everyone, keep it public but write the read rule down and make sure only signed-in users can upload into their own folder.",
    )
    return TraceOut(
        ghost_path=ghost,
        attack_path=attack,
        fix=FixOut(
            explanation=explanation,
            diff=_new_file_diff(_next_migration(ctx, f"heist_storage_{s}"), sql),
            prompt=(
                f"{ctx.tool}, please add Supabase storage policies for the {bucket} bucket. "
                + (
                    "Keep public reads, but only let signed-in users upload, into a folder named "
                    "after their user id. "
                    if reason == "public_no_policy"
                    else "Each signed-in user should only read and upload files in a folder named "
                    "after their user id"
                    + (
                        ", and the bucket should be private. "
                        if reason == "public_sensitive_no_policy"
                        else ". "
                    )
                )
                + "Store uploads under that folder and add the rules as a new migration."
            ),
        ),
    )


# --- mistakes 5, 6, 7: side doors -------------------------------------------------------


def _door(ctx: _Ctx) -> tuple[Node, CodeRef] | None:
    f = ctx.f
    node = next(
        (n for i in f.node_ids if (n := ctx.node(i)) and n.kind in ("function", "route")), None
    )
    ref = f.refs[0] if f.refs else (node.ref if node else None)
    if ref is None:
        return None
    return (node or _node_for_ref(ctx, ref)), ref


def _door_kind(rel: str) -> str:
    return "Edge Function" if _is_edge_function(rel) else "server route"


def _ghost_door(ctx: _Ctx, door: Node, end: Node | None) -> list[StepOut]:
    page = _front(ctx, [door.id])
    ghost = [_visitor(ctx, "A customer walks up to the shop.")]
    if page:
        ghost.append(
            _at(
                page,
                "a request with the user's session",
                "In the shop window, the page sends the customer to a side door.",
                "The page is only a suggestion. The side door must check for itself.",
                f"{page.name} calls {door.name}.",
            )
        )
    ghost.append(
        _desk(
            ctx,
            "They show their ID at the guard desk and get a pass.",
            "The pass is how the side door knows who is knocking.",
            "The request carries the user's access token in the Authorization header.",
            "a signed-in user's token",
        )
    )
    ghost.append(
        _at(
            door,
            "a checked user",
            f"At the side door {door.name}, the doorman reads the pass before letting them in.",
            "Checking the pass on the server is the only check an attacker cannot skip.",
            "The handler calls auth.getUser() and stops with 401 when there is no user.",
        )
    )
    if end is not None and len(ghost) < 5:
        ghost.append(
            _at(
                end,
                "only what this user may touch",
                f"Behind the door, they only reach {end.name} on their own behalf.",
                "Everything after the door acts for one known user.",
                f"The function uses {end.name} for the checked user only.",
            )
        )
    return ghost


def _m5(ctx: _Ctx) -> TraceOut:
    found = _door(ctx)
    if found is None:
        return _m0(ctx)
    door, ref = found
    kind = _door_kind(ref.file)
    after = _downstream(ctx, door.id)
    ghost = _ghost_door(ctx, door, after[0] if after else None)

    attack = [_visitor(ctx, "Someone with bad intentions walks around the back of the shop.")]
    attack.append(
        _at_ref(
            door,
            ref,
            "a request with no pass at all",
            f"The side door {door.name} has no doorman. They walk straight in.",
            f"A {kind} is reachable by anyone on the internet. Without a sign-in check, it works for strangers too.",
            f"{ref.file} line {ref.start_line} starts handling the request without checking who sent it.",
        )
    )
    for extra in ctx.f.refs[1:2]:
        attack.append(
            _at_ref(
                door,
                extra,
                "no token required",
                "The sign that says 'staff only' has been taken down.",
                "verify_jwt = false tells Supabase not to require a signed-in token before running the function.",
                f"{extra.file} line {extra.start_line} turns off the platform's own token check.",
            )
        )
    for n in after:
        attack.append(
            _at(
                n,
                "whatever the stranger asked for",
                f"From inside, they use {n.name} as if they were the shop.",
                "Everything behind the door trusts that the door already checked.",
                f"The function reaches {n.name} with the app's own credentials.",
            )
        )
    if len(attack) < 3:
        attack.append(
            _desk(
                ctx,
                "They never stopped at the guard desk.",
                "The guard desk only helps if the door asks to see a pass.",
                "No auth.getUser() call, so Supabase Auth is never consulted.",
                "no session",
            )
        )

    line, req = _handler(ctx, ref)
    lines = ctx.lines(ref.file)
    indent = _indent(lines[line] if lines and line < len(lines) else None)
    action = door.id.startswith("route:action:")
    edits = _import_edits(ctx, ref.file) + [
        (line, [], _auth_lines(ref.file, req, indent, action=action))
    ]
    diff = _file_diff(ref.file, edits)
    jwt_fixed = False
    if len(ctx.f.refs) > 1 and ctx.f.refs[1].file.endswith("config.toml"):
        cfg = ctx.f.refs[1]
        cfg_lines = ctx.lines(cfg.file)
        if cfg_lines and cfg.start_line <= len(cfg_lines):
            old = cfg_lines[cfg.start_line - 1]
            new = old.replace("false", "true")
            diff += "\n" + _file_diff(cfg.file, [(cfg.start_line, [old], [new])])
            jwt_fixed = True
    return TraceOut(
        ghost_path=ghost,
        attack_path=attack,
        fix=FixOut(
            explanation=(
                f"Anyone on the internet can call {door.name}, signed in or not. Add a check at the "
                "start of the handler that asks Supabase who the user is and stops with a 401 "
                "error when nobody is signed in"
                f"{', and turn verify_jwt back on' if jwt_fixed else ''}."
            ),
            diff=diff,
            prompt=(
                f"{ctx.tool}, please make {door.name} require a signed-in user. At the start of the "
                "handler, call supabase.auth.getUser() with the request's Authorization header and "
                "return a 401 error if there is no user. Do not turn off JWT verification for it."
            ),
        ),
    )


def _m6(ctx: _Ctx) -> TraceOut:
    found = _door(ctx)
    if found is None:
        return _m0(ctx)
    door, ref = found
    lines = ctx.lines(ref.file)
    old = lines[ref.start_line - 1] if lines and ref.start_line <= len(lines) else None
    m = _FROM_RE.search(old or "")
    tables = [n for n in _downstream(ctx, door.id, 5) if n.kind == "table"]
    table = (ctx.node(f"table:{m.group(1)}") if m else None) or (tables[0] if tables else None)
    owner = (_owner_column(ctx, table.name) if table else None) or "user_id"
    ghost = _ghost_door(ctx, door, table)

    attack = [_visitor(ctx, "Someone signs up as a normal customer.", "their own account")]
    attack.append(
        _desk(
            ctx,
            "They get a real pass at the guard desk. Nothing looks wrong yet.",
            "Signing in is fine. The problem is what the door does next.",
            "The user has a valid session, like any customer.",
            "a valid session for their own account",
        )
    )
    attack.append(
        _at_ref(
            door,
            ref,
            "an id of a record that belongs to someone else",
            f"At the side door {door.name}, they hand over a ticket number for someone else's box, and the door takes it at face value.",
            "The function uses the master key and trusts the id in the request, so nothing ties the record to the caller.",
            f"{ref.file} line {ref.start_line} updates the record whose id came from the request body, with no owner filter.",
        )
    )
    if table:
        attack.append(
            _at(
                table,
                f"another user's row in {table.name}",
                f"In the vault, they rewrite a box in {table.name} that is not theirs.",
                "The service role skips row level security, so the function itself must check ownership.",
                f"The update on {table.name} matches by id only.",
            )
        )

    line, req = _handler(ctx, ref)
    hl = ctx.lines(ref.file)
    indent = _indent(hl[line] if hl and line < len(hl) else None)
    edits = _import_edits(ctx, ref.file)
    edits.append(
        (line, [], _auth_lines(ref.file, req, indent, action=door.id.startswith("route:action:")))
    )
    if old is not None and _EQ_RE.search(old):
        eq = _EQ_RE.search(old)
        assert eq is not None
        new = old[: eq.end()] + f".eq('{owner}', user.id)" + old[eq.end() :]
        edits.append((ref.start_line, [old], [new]))
    else:
        edits.append(
            (
                ref.start_line - 1,
                [],
                [f"{_indent(old)}// add .eq('{owner}', user.id) to the query below"],
            )
        )
    return TraceOut(
        ghost_path=ghost,
        attack_path=attack,
        fix=FixOut(
            explanation=(
                f"{door.name} changes records using the admin key and trusts the record id sent by "
                "the browser, so one user can change another user's data. Check who is signed in, "
                f"then only touch rows where {owner} matches that user."
            ),
            diff=_file_diff(ref.file, edits),
            prompt=(
                f"{ctx.tool}, please fix {door.name} so users can only change their own records. "
                "Get the signed-in user with supabase.auth.getUser() and return 401 if there is "
                f"none, then add .eq('{owner}', user.id) to the query so it only matches rows the "
                "user owns."
            ),
        ),
    )


def _m7(ctx: _Ctx) -> TraceOut:
    found = _door(ctx)
    if found is None:
        return _m0(ctx)
    door, ref = found
    host = ctx.ev("host", "")
    ext = ctx.node(f"ext:{host}") or next(
        (n for n in _downstream(ctx, door.id) if n.kind == "external_api"), None
    )
    vendor = _vendor(host or (ext.name if ext else ""))
    ghost = _ghost_door(ctx, door, ext)

    attack = [
        _visitor(
            ctx,
            "Someone with bad intentions finds the side door, with a script that knocks thousands of times.",
            "no account, many requests",
        )
    ]
    attack.append(
        _at_ref(
            door,
            ref,
            "a request from a stranger, repeated without limit",
            f"The side door {door.name} lets anyone in and runs to the supplier for every knock.",
            "Each call costs money. With no sign-in and no limit, a stranger decides how much you spend.",
            f"{ref.file} line {ref.start_line} calls {vendor} for every request, with no user check and no rate limit.",
        )
    )
    if ext:
        attack.append(
            _at(
                ext,
                "a paid request on your account",
                f"Across the road, {vendor} bills you for every order.",
                "The provider charges the key's owner, which is you.",
                f"Requests to {vendor} use the app's own key from the function secrets.",
            )
        )
    if len(attack) < 3:
        attack.append(
            _desk(
                ctx,
                "They never stop at the guard desk.",
                "Without a pass check there is no one to count requests against.",
                "No auth.getUser() call before the paid request.",
                "no session",
            )
        )

    lines = ctx.lines(ref.file)
    at_line = ref.start_line - 1
    indent = _indent(lines[ref.start_line - 1] if lines and ref.start_line <= len(lines) else None)
    _, req = _handler(ctx, ref)
    edge = _is_edge_function(ref.file)
    deny = (
        "return new Response('Too many requests', { status: 429 })"
        if edge
        else "return Response.json({ error: 'Too many requests' }, { status: 429 })"
    )
    limit = [
        f"{indent}const since = new Date(Date.now() - 60 * 60 * 1000).toISOString()",
        f"{indent}const {{ count }} = await authClient",
        f"{indent}  .from('ai_usage')",
        f"{indent}  .select('id', {{ count: 'exact', head: true }})",
        f"{indent}  .eq('user_id', user.id)",
        f"{indent}  .gte('created_at', since)",
        f"{indent}if ((count ?? 0) >= 20) {deny}",
        f"{indent}await authClient.from('ai_usage').insert({{ user_id: user.id }})",
    ]
    edits = _import_edits(ctx, ref.file)
    edits.append(
        (
            at_line,
            [],
            _auth_lines(ref.file, req, indent, action=door.id.startswith("route:action:")) + limit,
        )
    )
    usage_sql = [
        "create table public.ai_usage (",
        "  id bigint generated always as identity primary key,",
        "  user_id uuid not null default auth.uid() references auth.users(id),",
        "  created_at timestamptz not null default now()",
        ");",
        "",
        "alter table public.ai_usage enable row level security;",
        "",
        'create policy "ai_usage_select_own" on public.ai_usage',
        "  for select to authenticated using ((select auth.uid()) = user_id);",
        'create policy "ai_usage_insert_own" on public.ai_usage',
        "  for insert to authenticated with check ((select auth.uid()) = user_id);",
    ]
    diff = (
        _file_diff(ref.file, edits)
        + "\n"
        + _new_file_diff(_next_migration(ctx, "heist_ai_usage"), usage_sql)
    )
    return TraceOut(
        ghost_path=ghost,
        attack_path=attack,
        fix=FixOut(
            explanation=(
                f"Anyone can call {door.name}, and every call spends your {vendor} credits. Require "
                "a signed-in user before the paid call, and keep a small usage table so each user "
                "gets at most 20 calls an hour. Requests over the limit get a 429 error."
            ),
            diff=diff,
            prompt=(
                f"{ctx.tool}, please protect {door.name}. Before it calls {vendor}, require a "
                "signed-in user with supabase.auth.getUser() and return 401 if there is none. Then "
                "add a per-user limit of 20 calls per hour, tracked in a new ai_usage table with "
                "row level security, and return 429 when a user goes over it."
            ),
        ),
    )


# --- mistake 0: anything else -----------------------------------------------------------


def _m0(ctx: _Ctx) -> TraceOut:
    f = ctx.f
    ref = f.refs[0] if f.refs else None
    where = _node_for_ref(ctx, ref) if ref else None
    page = _front(ctx, [], any_page=True)
    ghost = [_visitor(ctx, "A customer walks up to the shop.")]
    ghost.append(
        _desk(
            ctx,
            "They check in at the guard desk and use the shop as intended.",
            "Supabase Auth identifies the user before anything sensitive happens.",
            "Requests carry the signed-in user's session.",
            "the user's session",
        )
    )

    attack = [_visitor(ctx, "Someone with bad intentions looks for a weak spot.")]
    if page and page is not where:
        attack.append(
            _at(
                page,
                "the public front end",
                "They study the shop window for anything left lying around.",
                "Everything in the front end is visible to every visitor.",
                f"{page.name} is downloaded by every browser.",
            )
        )
    if where and ref:
        attack.append(
            _at_ref(
                where,
                ref,
                "the weak spot",
                f"Here is the weak spot the scanner found: {f.title}.",
                "This pattern is a known way for apps to get broken into, so it is worth fixing even if it looks harmless.",
                f"{ref.file} line {ref.start_line} matches the check that flagged this problem.",
            )
        )
    while len(attack) < 3:
        attack.append(
            _desk(
                ctx,
                "They see whether the guard desk notices them.",
                "Every request should be tied to a signed-in user before it touches data.",
                "Check that this code path verifies the user.",
                "an unchecked request",
            )
        )

    loc = f"{ref.file} line {ref.start_line}" if ref else "the flagged code"
    note = re.sub(r"\s+", " ", f.title).strip()
    diff = (
        _file_diff(ref.file, [(max(ref.start_line - 1, 0), [], [f"// SECURITY: {note}"])])
        if ref
        else _new_file_diff("SECURITY.md", [f"- {note}"])
    )
    return TraceOut(
        ghost_path=ghost,
        attack_path=attack,
        fix=FixOut(
            explanation=f"A security check flagged {loc}: {note}. Review that code and change it so it no longer matches the risky pattern.",
            diff=diff,
            prompt=f"{ctx.tool}, a security scan flagged {loc}: {note}. Please fix this safely without changing what the app does for normal users.",
        ),
    )


_TEMPLATES: dict[int, Callable[[_Ctx], TraceOut]] = {
    0: _m0,
    1: _m1,
    2: _m2,
    3: _m3,
    4: _m4,
    5: _m5,
    6: _m6,
    7: _m7,
}


def fallback_trace(f: Finding, g: AppGraph, ws: Workspace | None = None) -> TraceOut:
    """A deterministic trace for the finding. Never raises."""
    nodes = {n.id: n for n in g.nodes}
    nodes.setdefault("visitor", Node(id="visitor", kind="visitor", name="Visitor", zone="street"))
    nodes.setdefault(
        "auth:supabase",
        Node(id="auth:supabase", kind="auth", name="Supabase Auth", zone="guard_desk"),
    )
    ctx = _Ctx(f=f, g=g, ws=ws, nodes=nodes)
    builder = _TEMPLATES.get(f.mistake, _m0)
    try:
        t = builder(ctx)
    except Exception:  # a fallback must always produce something
        log.exception("template for mistake %d failed on %s", f.mistake, f.id)
        t = _m0(ctx)
    return scrub_dashes(t)
