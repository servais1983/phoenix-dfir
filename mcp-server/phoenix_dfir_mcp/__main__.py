"""Phoenix DFIR command line (`phoenix`).

- serve-mcp   : start the stdio MCP server (alias: serve)
- tools       : list the DFIR tools
- doctor      : check the installation (LLM, external tools, modules, storage)
- ingest      : copy evidence into a case, hash it and make it read-only
- triage      : deterministic triage of a case, no LLM needed
- verify      : check the evidence against manifest.sha256
- investigate : autonomous investigation by the local LLM (falls back to triage)
- eval        : measure the investigator on an annotated case suite
- web         : start the investigator console (waitress, every OS)
- models      : local LLM servers, their models and the model chosen per role
"""

import argparse
import json
import sys

from . import __version__


def _triage(case_dir, fmt, output, derived_dir, workers=None):
    import hashlib
    import os
    from . import ledger, triage, workspace
    if workspace.has_layout(case_dir):
        # Standard layout: derived data in derived/, reports in reports/
        derived_dir = derived_dir or os.path.join(case_dir, workspace.DERIVED_DIR)
        output = output or os.path.join(case_dir, 'reports')
    try:
        report = triage.run_triage(case_dir, derived_dir=derived_dir, workers=workers)
    except ValueError as e:
        print(f'Error: {e}', file=sys.stderr)
        return 2
    text = triage.to_json(report)
    print(text if fmt == 'json' else triage.render_markdown(report), end='')
    if output:
        paths = triage.write_report(report, output)
        print(f"Reports: {', '.join(paths)}", file=sys.stderr)
    try:
        s = report['summary']
        ledger.record('triage_run', agent='phoenix-triage', artifact_ref=os.path.abspath(case_dir),
                      summary=f"Deterministic triage: {s['findings']} finding(s) on {s['artifacts']} artifact(s)",
                      payload_sha256=hashlib.sha256(text.encode('utf-8')).hexdigest(),
                      details={'summary': s, 'reports': list(paths) if output else []})
    except ledger.LedgerError as e:
        print(f'Warning: triage not recorded in the custody ledger ({e})', file=sys.stderr)
    return 0


def _models(provider, check, as_json):
    from . import copilot, models
    if provider and provider not in copilot.PROVIDERS:
        print(f'Error: unknown provider {provider!r} ({", ".join(copilot.PROVIDERS)})', file=sys.stderr)
        return 2
    plan = models.plan(provider)
    plan['servers'] = [{'provider': p, 'reachable': copilot.llm_reachable(p)} for p in copilot.LOCAL_PROVIDERS]
    if check:
        for role, info in plan['roles'].items():
            if role in ('investigator', 'extractor'):  # roles that need tool calling or strict output
                info['tool_calling'] = models.probe_tool_calling(plan['provider'], info['model'])
    if as_json:
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        return 0
    print(f"Provider: {plan['label']} ({plan['provider']}), comfortable size up to {plan['max_params_b']:g}B")
    for server in plan['servers']:
        print(f"  {server['provider']:<9} {'reachable' if server['reachable'] else 'not reachable'}")
    print(f"Available models ({len(plan['available'])}): {', '.join(plan['available']) or 'none listed'}")
    for role, info in plan['roles'].items():
        line = f"  {role:<12} {info['model']}  [{info['source']}"
        line += f", score {info['score']}]" if info['score'] is not None else ']'
        if 'tool_calling' in info:
            tc = info['tool_calling']
            line += f"  tool calling: {'OK' if tc['ok'] else 'FAILED'} ({tc['seconds']}s, {tc['detail']})"
        print(line)
    return 0


def _ingest(case_dir, paths):
    from . import casefile, ledger
    try:
        result = casefile.ingest(case_dir, paths)
    except (casefile.CaseError, ledger.LedgerError, OSError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 2
    for item in result['added']:
        print(f"{item['sha256']}  {item['path']}")
    for warning in result['warnings']:
        print(f'Warning: {warning}', file=sys.stderr)
    print(f"Manifest: {result['manifest']}", file=sys.stderr)
    return 0


def _verify(case_dir, as_json):
    from . import casefile, ledger
    try:
        result = casefile.verify(case_dir)
    except (casefile.CaseError, ledger.LedgerError, OSError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"{'VALID' if result['valid'] else 'INTEGRITY FAILURE'}: {result['ok']}/{result['checked']} "
              f"evidence files match {casefile.MANIFEST}")
        for item in result['mismatched']:
            print(f"  modified: {item['path']} (expected {item['expected']}, got {item['actual']})")
        for rel in result['missing']:
            print(f'  missing: {rel}')
        for rel in result['unlisted']:
            print(f'  not in the manifest: {rel}')
        print(f"Ledger entry #{result['ledger_seq']}, record {result['record']}")
    return 0 if result['valid'] else 1


def _rules(args):
    import zipfile
    from . import sigma_engine
    if args.rules_command == 'sync':
        try:
            result = sigma_engine.sync(expected_sha256=args.sha256)
        except Exception as e:  # network or digest failure: reported, nothing half written is loaded
            print(f'phoenix rules sync: {type(e).__name__}: {e}', file=sys.stderr)
            return 1
        print(f"SigmaHQ {result['tag']}: {result['rules']} rule files in {result['target']} "
              f"(sha256 {result['sha256']})")
        return 0
    if args.rules_command == 'import':
        try:
            result = sigma_engine.import_archive(args.archive, name=args.name)
        except (OSError, ValueError, zipfile.BadZipFile) as e:
            print(f'phoenix rules import: {type(e).__name__}: {e}', file=sys.stderr)
            return 1
        print(f"{result['rules']} rule files imported into {result['target']} "
              f"({result['skipped']} other entries skipped, sha256 {result['sha256']})")
        return 0
    if args.rules_command == 'export-builtin':
        paths = sigma_engine.export_builtin(args.target) if args.target else sigma_engine.export_builtin()
        print(f'{len(paths)} built in rules written as Sigma YAML in {paths[0].parent if paths else args.target}')
        return 0
    status = sigma_engine.status()
    rules, errors = sigma_engine.load_rules([sigma_engine.connector_rules_path()])
    report = {'pysigma': status, 'builtin_rules': len(sigma_engine.builtin_rules()),
              'rules': len(rules), 'invalid': len(errors),
              'by_folder': {str(d): sigma_engine.count_rules(d) for d in status.get('dirs', [])}}
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    print(f"Built in rules: {report['builtin_rules']} (always run)")
    if not status['available']:
        print(f"pySigma: {status['detail']}")
        return 0
    print(f"pySigma {status.get('pysigma')}: {report['rules']} usable rules, {report['invalid']} invalid")
    for folder, counts in report['by_folder'].items():
        print(f"  {folder}: {counts['usable']} usable, {counts['invalid']} invalid")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='phoenix',
        description='Phoenix DFIR: local-first forensic toolkit, deterministic triage and LLM investigator',
    )
    parser.add_argument('--version', action='version', version=f'phoenix-dfir {__version__}')
    sub = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('serve-mcp', aliases=['serve'], help='Start the stdio MCP server')
    sub.add_parser('tools', help='List the available DFIR tools')
    p_mod = sub.add_parser('models', help='Local LLM servers, their models and the model chosen per role')
    p_mod.add_argument('--provider', default=None, help='ollama, llamacpp, lmstudio or jan (default: configured)')
    p_mod.add_argument('--check', action='store_true',
                       help='Ask each chosen model for one real tool call (local server must be running)')
    p_mod.add_argument('--json', action='store_true', help='JSON output')

    p_web = sub.add_parser('web', help='Start the investigator console (waitress, every OS)')
    p_web.add_argument('--host', default=None, help='Listen address (default 127.0.0.1, or PHOENIX_HOST)')
    p_web.add_argument('--port', type=int, default=None, help='Port (default 5000, or PHOENIX_PORT)')
    p_web.add_argument('--threads', type=int, default=None, help='Worker threads (default PHOENIX_THREADS or 16)')

    p_rules = sub.add_parser('rules', help='Sigma rules: list, sync SigmaHQ, import an archive, export built in')
    rules_sub = p_rules.add_subparsers(dest='rules_command')
    p_rl = rules_sub.add_parser('list', help='Rule folders and how many rules pySigma can run')
    p_rl.add_argument('--json', action='store_true', help='JSON output')
    p_rs = rules_sub.add_parser('sync', help='Download the pinned SigmaHQ release into the data folder')
    p_rs.add_argument('--sha256', default=None, help='Refuse an archive with another SHA-256 digest')
    p_ri = rules_sub.add_parser('import', help='Import the Sigma rules of a zip archive')
    p_ri.add_argument('archive', help='Zip archive of Sigma rules (.yml / .yaml)')
    p_ri.add_argument('--name', default=None, help='Folder name in the rule store (default: archive name)')
    p_re = rules_sub.add_parser('export-builtin', help='Write the built in rules as Sigma YAML')
    p_re.add_argument('target', nargs='?', default=None, help='Target folder (default: the packaged folder)')

    p_doc = sub.add_parser('doctor', help='Check this installation: LLM, external tools, modules, storage')
    p_doc.add_argument('--json', action='store_true', help='JSON output')

    p_tri = sub.add_parser('triage', help='Deterministic triage of a case (no LLM)')
    p_tri.add_argument('case_dir', help='Case folder')
    p_tri.add_argument('--format', choices=['md', 'json'], default='md', help='Output format (default: md)')
    p_tri.add_argument('-o', '--output', default=None,
                       help='Folder that receives triage.json and triage.md (default: print only)')
    p_tri.add_argument('--derived-dir', default=None,
                       help='Keep derived data (extracted files) in this folder instead of a temporary one')
    p_tri.add_argument('--workers', type=int, default=None,
                       help='Artifacts analyzed at the same time (default PHOENIX_EXTRACTION_WORKERS or up to 4); '
                            'the report does not depend on it')

    p_ag = sub.add_parser('agents', help='Specialized agents: model role, phases, tools, budget, contract')
    p_ag.add_argument('--json', action='store_true', help='JSON output')
    p_sch = sub.add_parser('schemas', help='JSON Schemas of the agent contracts')
    p_sch.add_argument('-o', '--output', default=None, help='Write one <name>.schema.json per contract here')

    p_ing = sub.add_parser('ingest', help='Copy evidence into <case>/evidence, hash it and make it read-only')
    p_ing.add_argument('case_dir', help='Case folder (the standard layout is created if needed)')
    p_ing.add_argument('paths', nargs='+', help='Evidence files or folders')

    p_ver = sub.add_parser('verify', help='Check the evidence against manifest.sha256 (result in the ledger)')
    p_ver.add_argument('case_dir', help='Case folder')
    p_ver.add_argument('--json', action='store_true', help='JSON output')

    p_inv = sub.add_parser('investigate', help='Autonomous investigation of a case by the local LLM')
    p_inv.add_argument('case_dir', help='Dossier contenant les artefacts du cas')
    p_inv.add_argument('-q', '--question', default=None,
                       help="Question ou contexte pour orienter l'enquete")
    p_inv.add_argument('-m', '--model', default=None,
                       help='LLM model (default: the provider model, e.g. PHOENIX_OLLAMA_MODEL)')
    p_inv.add_argument('--max-steps', type=int, default=None,
                       help="Nombre max de tours d'orchestration (budget global)")
    p_inv.add_argument('--mode', choices=['phased', 'loop'], default=None,
                       help="Moteur : phased (5 phases a portes qualite, defaut) ou loop")
    p_inv.add_argument('--no-triage-fallback', action='store_true',
                       help='Fail instead of running the deterministic triage when no LLM answers')

    p_eval = sub.add_parser('eval', help="Evaluer l'enqueteur sur une suite de cas annotes")
    p_eval.add_argument('suite_dir', help='Dossier de la suite (un sous-dossier + ground_truth.json par cas)')
    p_eval.add_argument('-m', '--model', default=None, help='Modele LLM (defaut : celui du fournisseur)')
    p_eval.add_argument('--case', action='append', default=None, help='Limiter a ce cas (repetable)')
    p_eval.add_argument('--mode', choices=['phased', 'loop'], default=None,
                        help="Moteur d'enquete (defaut : phased) - pour comparer les deux")
    p_eval.add_argument('--max-steps', type=int, default=None, help="Tours max d'orchestration par cas")
    p_eval.add_argument('-o', '--output', default=None, help='Prefixe des rapports (.json et .md)')
    p_eval.add_argument('--min-recall', type=float, default=None, help='Seuil de rappel des techniques (0-1)')
    p_eval.add_argument('--max-forbidden', type=int, default=None,
                        help='Nombre max de techniques interdites rapportees')
    p_eval.add_argument('--min-pass-rate', type=float, default=None, help='Taux min de cas reussis (0-1)')
    p_eval.add_argument('--min-fact-exact', type=float, default=None,
                        help='Taux min de reponses exactes du corrige factuel (0-1)')
    p_eval.add_argument('-v', '--verbose', action='store_true', help="Afficher le journal de l'enqueteur")

    args = parser.parse_args(argv)

    if args.command in ('serve', 'serve-mcp'):
        from . import pathpolicy, server
        # Served to an MCP client: no file access until PHOENIX_TOOL_ROOTS is set
        pathpolicy.set_strict(True)
        if not pathpolicy.active_roots():
            print('phoenix serve-mcp: no allowed folder, set PHOENIX_TOOL_ROOTS to the case folders.',
                  file=sys.stderr)
        server.serve()
        return 0

    if args.command == 'agents':
        from . import agents, toolkit
        rows = agents.describe()
        for row in rows:
            row['tools_available'] = [t for t in sorted(toolkit.TOOLS) if agents.AGENTS[row['name']].allows(t)]
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return 0
        for row in rows:
            contract = f", contract {row['contract']}" if row['contract'] else ''
            print(f"{row['name']}: {row['title']} (role {row['role']}, phases {', '.join(row['phases']) or '-'}, "
                  f"{row['max_tokens']} tokens{contract})")
            print(f"  {row['mission']}")
            print(f"  tools: {', '.join(row['tools_available']) or '-'}")
        return 0

    if args.command == 'schemas':
        from pathlib import Path
        from . import contracts
        schemas = contracts.json_schemas()
        if not args.output:
            print(json.dumps(schemas, indent=2, ensure_ascii=False, sort_keys=True))
            return 0
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        for name, schema in schemas.items():
            (out / f'{name}.schema.json').write_text(
                json.dumps(schema, indent=2, ensure_ascii=False, sort_keys=True) + '\n', encoding='utf-8')
        print(f'{len(schemas)} schemas written in {out}')
        return 0

    if args.command == 'rules':
        if not args.rules_command:
            args.rules_command, args.json = 'list', False
        return _rules(args)

    if args.command == 'models':
        return _models(args.provider, args.check, args.json)

    if args.command == 'web':
        from . import web
        return web.serve(args.host, args.port, args.threads)

    if args.command == 'doctor':
        from . import doctor
        report = doctor.collect()
        print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else doctor.render_text(report), end='')
        if args.json:
            print()
        return 0

    if args.command == 'triage':
        return _triage(args.case_dir, args.format, args.output, args.derived_dir, args.workers)

    if args.command == 'ingest':
        return _ingest(args.case_dir, args.paths)

    if args.command == 'verify':
        return _verify(args.case_dir, args.json)

    if args.command == 'tools':
        from . import toolkit
        for t in toolkit.list_tools():
            print(f"- {t['name']}: {t['description'].splitlines()[0]}")
        return 0

    if args.command == 'investigate':
        from . import copilot, investigator
        from .copilot import CopilotError
        fallback = not args.no_triage_fallback
        if fallback and not copilot.llm_reachable():
            print(f'No LLM reachable ({copilot.provider_label()}): running the deterministic triage instead. '
                  'Start Ollama, llama.cpp, LM Studio or Jan to enable the LLM investigation.', file=sys.stderr)
            return _triage(args.case_dir, 'md', None, None)
        kwargs = {'question': args.question, 'model': args.model, 'mode': args.mode,
                  'on_step': lambda msg: print(msg, file=sys.stderr)}
        if args.max_steps:
            kwargs['max_steps'] = args.max_steps
        try:
            result = investigator.investigate(args.case_dir, **kwargs)
        except CopilotError as e:
            print(f'Erreur: {e}', file=sys.stderr)
            if not fallback:
                return 1
            print('LLM investigation failed: running the deterministic triage instead.', file=sys.stderr)
            return _triage(args.case_dir, 'md', None, None)
        print('\n===== RESUME EXECUTIF =====\n')
        print(result['summary'])
        if result.get('report_path'):
            print(f"\nRapport complet : {result['report_path']}")
        m = result.get('metrics', {})
        if m:
            print(f"\nConstats : {m.get('findings', 0)} (dont {m.get('findings_critical_or_high', 0)} "
                  f"critiques/hauts) | Hypotheses confirmees : {m.get('hypotheses_confirmed', 0)}")
            print(f"Revue adviser : {m.get('adviser_verdict') or 'n/a'}")
            print(f"Observabilite : {m.get('llm_calls', 0)} appels LLM, {m.get('total_tokens', 0)} tokens, "
                  f"{m.get('tools_executed', 0)} outils")
        print(f"\n({result['steps']} tours)", file=sys.stderr)
        print(json.dumps({'report_path': result.get('report_path'), 'steps': result['steps'],
                          'metrics': m}, ensure_ascii=False), file=sys.stderr)
        return 0

    if args.command == 'eval':
        from . import evaluation
        log = (lambda msg: print(msg, file=sys.stderr)) if args.verbose else None
        try:
            report = evaluation.run_suite(args.suite_dir, model=args.model, max_steps=args.max_steps,
                                          only=args.case, log=log, mode=args.mode)
        except ValueError as e:
            print(f'Erreur: {e}', file=sys.stderr)
            return 2
        markdown = evaluation.render_markdown(report)
        print(markdown)
        if args.output:
            with open(args.output + '.json', 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            with open(args.output + '.md', 'w', encoding='utf-8') as f:
                f.write(markdown)
            print(f'Rapports : {args.output}.json, {args.output}.md', file=sys.stderr)
        failures = evaluation.check_thresholds(report, args.min_recall, args.max_forbidden,
                                               args.min_pass_rate, args.min_fact_exact)
        for failure in failures:
            print(f'SEUIL NON ATTEINT : {failure}', file=sys.stderr)
        return 1 if failures else 0

    return 1


if __name__ == '__main__':
    sys.exit(main())
