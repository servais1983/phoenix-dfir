"""Phoenix DFIR command line (`phoenix`).

- serve-mcp   : start the stdio MCP server (alias: serve)
- tools       : list the DFIR tools
- ingest      : copy evidence into a case, hash it and make it read-only
- triage      : deterministic triage of a case, no LLM needed
- verify      : check the evidence against manifest.sha256
- investigate : autonomous investigation by the local LLM (falls back to triage)
- eval        : measure the investigator on an annotated case suite
"""

import argparse
import json
import sys

from . import __version__


def _triage(case_dir, fmt, output, derived_dir):
    import hashlib
    import os
    from . import ledger, triage, workspace
    if workspace.has_layout(case_dir):
        # Standard layout: derived data in derived/, reports in reports/
        derived_dir = derived_dir or os.path.join(case_dir, workspace.DERIVED_DIR)
        output = output or os.path.join(case_dir, 'reports')
    try:
        report = triage.run_triage(case_dir, derived_dir=derived_dir)
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


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='phoenix',
        description='Phoenix DFIR: local-first forensic toolkit, deterministic triage and LLM investigator',
    )
    parser.add_argument('--version', action='version', version=f'phoenix-dfir {__version__}')
    sub = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('serve-mcp', aliases=['serve'], help='Start the stdio MCP server')
    sub.add_parser('tools', help='List the available DFIR tools')

    p_tri = sub.add_parser('triage', help='Deterministic triage of a case (no LLM)')
    p_tri.add_argument('case_dir', help='Case folder')
    p_tri.add_argument('--format', choices=['md', 'json'], default='md', help='Output format (default: md)')
    p_tri.add_argument('-o', '--output', default=None,
                       help='Folder that receives triage.json and triage.md (default: print only)')
    p_tri.add_argument('--derived-dir', default=None,
                       help='Keep derived data (extracted files) in this folder instead of a temporary one')

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

    if args.command == 'triage':
        return _triage(args.case_dir, args.format, args.output, args.derived_dir)

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
                  'Start Ollama or llama.cpp to enable the LLM investigation.', file=sys.stderr)
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
