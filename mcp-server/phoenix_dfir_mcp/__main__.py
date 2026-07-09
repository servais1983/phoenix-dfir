"""CLI Phoenix DFIR MCP.

- serve       : demarrer le serveur MCP stdio (pour GitHub Copilot mode agent)
- tools       : lister les outils DFIR exposes
- investigate : resoudre un cas de maniere autonome via GitHub Copilot
"""

import argparse
import json
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='phoenix_dfir_mcp',
        description='Phoenix DFIR MCP - outils forensiques orchestres par GitHub Copilot',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('serve', help='Demarrer le serveur MCP stdio')
    sub.add_parser('tools', help='Lister les outils DFIR disponibles')

    p_inv = sub.add_parser('investigate', help='Investigation autonome d\'un cas par GitHub Copilot')
    p_inv.add_argument('case_dir', help='Dossier contenant les artefacts du cas')
    p_inv.add_argument('-q', '--question', default=None,
                       help="Question ou contexte pour orienter l'enquete")
    p_inv.add_argument('-m', '--model', default=None,
                       help='Modele GitHub Models (defaut: PHOENIX_GITHUB_MODEL ou openai/gpt-4o-mini)')
    p_inv.add_argument('--max-steps', type=int, default=None,
                       help="Nombre max de tours d'orchestration (defaut 40)")

    args = parser.parse_args(argv)

    if args.command == 'serve':
        from . import server
        server.serve()
        return 0

    if args.command == 'tools':
        from . import toolkit
        for t in toolkit.list_tools():
            print(f"- {t['name']}: {t['description'].splitlines()[0]}")
        return 0

    if args.command == 'investigate':
        from . import investigator
        from .copilot import CopilotError
        kwargs = {'question': args.question, 'model': args.model,
                  'on_step': lambda msg: print(msg, file=sys.stderr)}
        if args.max_steps:
            kwargs['max_steps'] = args.max_steps
        try:
            result = investigator.investigate(args.case_dir, **kwargs)
        except CopilotError as e:
            print(f'Erreur: {e}', file=sys.stderr)
            return 1
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

    return 1


if __name__ == '__main__':
    sys.exit(main())
