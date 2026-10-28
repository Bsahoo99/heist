from heist.fetch import load_workspace
from heist.graph.build import build_app_graph
from heist.graph.js import scan_js


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_graph_links_pages_to_tables_functions_buckets(vuln_app_path):
    ws = load_workspace(vuln_app_path)
    g = build_app_graph(ws, "vite_supabase")
    e = {(x.src, x.dst, x.kind) for x in g.edges}
    assert ("page:src/pages/Pets.tsx", "table:pets", "queries") in e
    assert ("page:src/pages/Requests.tsx", "fn:update-request", "invokes") in e
    assert ("page:src/pages/Upload.tsx", "bucket:id-documents", "uploads") in e
    assert ("fn:ai-describe", "ext:api.openai.com", "calls_external") in e
    assert ("fn:update-request", "table:adoption_requests", "queries") in e
    assert len(e) == len(g.edges)


def test_zones_and_flags(vuln_app_path):
    g = build_app_graph(load_workspace(vuln_app_path), "vite_supabase")
    assert g.node("table:messages").zone == "vault"
    assert g.node("fn:send-email").zone == "side_doors"
    assert g.node("page:src/pages/Pets.tsx").zone == "shop_window"
    assert g.node("bucket:id-documents").zone == "warehouse"
    assert g.node("ext:api.resend.com").zone == "across_road"
    assert g.node("auth:supabase").zone == "guard_desk"
    assert g.has_db_rules is True
    ids = [n.id for n in g.nodes]
    assert len(ids) == len(set(ids))


def test_every_node_ref_exists(vuln_app_path):
    g = build_app_graph(load_workspace(vuln_app_path), "vite_supabase")
    for n in g.nodes:
        if n.ref:
            lines = (vuln_app_path / n.ref.file).read_text().splitlines()
            assert 1 <= n.ref.start_line <= n.ref.end_line <= len(lines)


def test_client_call_nodes(vuln_app_path):
    g = build_app_graph(load_workspace(vuln_app_path), "vite_supabase")
    n = g.node("client:src/pages/Pets.tsx:9")
    assert n.kind == "client_call"
    assert n.name == "from('pets')"
    assert n.ref is not None and n.ref.start_line == 9


def test_clean_app_builds(clean_app_path):
    g = build_app_graph(load_workspace(clean_app_path), "vite_supabase")
    assert g.nodes


def test_non_literal_arguments_skipped(tmp_path):
    _write(
        tmp_path,
        "src/A.tsx",
        "const t = 'x'\nsupabase.from(t).select()\nsupabase.from(`a${t}`)\n"
        "fetch(url)\nfetch('http://insecure.test/x')\nfetch('/rel')\n"
        "supabase.functions.invoke(name)\n",
    )
    nodes, edges = scan_js(load_workspace(tmp_path))
    assert edges == []
    assert not [n for n in nodes if n.kind != "page"]


def test_template_literal_without_substitution(tmp_path):
    _write(tmp_path, "src/A.tsx", "supabase.from(`pets`).select()\n")
    _, edges = scan_js(load_workspace(tmp_path))
    assert [(e.src, e.dst, e.kind) for e in edges] == [("page:src/A.tsx", "table:pets", "queries")]


def test_malformed_and_binary_files_do_not_raise(tmp_path):
    _write(tmp_path, "src/Bad.tsx", "supabase.from('pets' <<< {{{ \n")
    (tmp_path / "src" / "bin.ts").write_bytes(b"\xff\xfe\x00bad")
    scan_js(load_workspace(tmp_path))


def test_next_route_and_server_action(tmp_path):
    _write(
        tmp_path,
        "app/(shop)/api/pets/[id]/route.ts",
        "export async function GET() {\n  return supabase.from('pets').select()\n}\n",
    )
    _write(
        tmp_path,
        "app/actions.ts",
        "'use server'\nexport async function go() {\n  await supabase.from('notes').select()\n}\n",
    )
    g = build_app_graph(load_workspace(tmp_path), "next_supabase")
    r = g.node("route:/api/pets/[id]")
    assert r.zone == "side_doors" and r.kind == "route"
    e = {(x.src, x.dst, x.kind) for x in g.edges}
    assert ("route:/api/pets/[id]", "table:pets", "queries") in e
    assert ("route:action:app/actions.ts", "table:notes", "queries") in e
    assert g.has_db_rules is False


def _assert_edges_resolve(g):
    ids = {n.id for n in g.nodes}
    for e in g.edges:
        assert e.src in ids and e.dst in ids, e


def test_edges_resolve_in_fixtures(vuln_app_path, clean_app_path):
    for p in (vuln_app_path, clean_app_path):
        _assert_edges_resolve(build_app_graph(load_workspace(p), "vite_supabase"))


def test_missing_function_nodes_are_synthesized(tmp_path):
    _write(
        tmp_path,
        "supabase/functions/hook/main.ts",
        "supabase.from('notes').select()\n",
    )
    _write(tmp_path, "src/A.tsx", "supabase.functions.invoke('ghost')\n")
    g = build_app_graph(load_workspace(tmp_path), "vite_supabase")
    _assert_edges_resolve(g)
    assert g.node("fn:hook").ref is None
    assert g.node("fn:ghost").zone == "side_doors"
    e = {(x.src, x.dst, x.kind) for x in g.edges}
    assert ("page:src/A.tsx", "fn:ghost", "invokes") in e
    assert ("fn:hook", "table:notes", "queries") in e


def test_empty_literal_skipped(tmp_path):
    _write(tmp_path, "src/A.tsx", "supabase.from('').select()\n")
    nodes, edges = scan_js(load_workspace(tmp_path))
    assert edges == [] and not [n for n in nodes if n.kind == "table"]


def test_escape_sequence_literal_skipped(tmp_path):
    _write(tmp_path, "src/A.tsx", "supabase.from('a\\nb').select()\n")
    nodes, edges = scan_js(load_workspace(tmp_path))
    assert edges == [] and not [n for n in nodes if n.kind == "table"]


def test_visitor_node_always_present(vuln_app_path, tmp_path):
    for ws in (load_workspace(vuln_app_path), load_workspace(tmp_path)):
        g = build_app_graph(ws, "vite_supabase")
        v = g.node("visitor")
        assert (v.kind, v.name, v.zone, v.ref) == ("visitor", "Visitor", "street", None)


def test_env_file_nodes(tmp_path):
    _write(tmp_path, ".env", "VITE_A=1\nVITE_B=2\n# note\n")
    _write(tmp_path, ".env.local", "VITE_C=3\n")
    _write(tmp_path, ".env.example", "VITE_A=\n")
    _write(tmp_path, "web/.env.sample", "VITE_A=\n")
    _write(tmp_path, ".env.template", "VITE_A=\n")
    _write(tmp_path, "supabase/functions/.env", "OPENAI_API_KEY=x\n")
    g = build_app_graph(load_workspace(tmp_path), "vite_supabase")
    env_nodes = {n.id: n for n in g.nodes if n.kind == "env_file"}
    assert set(env_nodes) == {"env:.env", "env:.env.local"}
    n = env_nodes["env:.env"]
    assert n.zone == "shop_window" and n.name == ".env"
    assert n.ref is not None and (n.ref.file, n.ref.start_line, n.ref.end_line) == (".env", 1, 3)
    _assert_edges_resolve(g)


def test_vuln_app_env_node(vuln_app_path):
    g = build_app_graph(load_workspace(vuln_app_path), "vite_supabase")
    n = g.node("env:.env")
    assert n.ref is not None and n.ref.end_line == 4


def test_storage_policies_live_in_the_warehouse(clean_app_path):
    g = build_app_graph(load_workspace(clean_app_path), "vite_supabase")
    assert g.node("policy:objects:pet_photos_read").zone == "warehouse"
    assert g.node("policy:objects:id_documents_insert_own").zone == "warehouse"
    assert g.node("policy:pets:pets_select_own").zone == "vault"
