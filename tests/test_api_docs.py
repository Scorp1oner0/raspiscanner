"""Guardrail contro la deriva della documentazione: ogni route Flask reale
deve comparire in API.md. Non verifica la qualita' della prosa (impossibile
da testare), solo che nessuna route sia stata aggiunta/rinominata senza
aggiornare il riferimento — il tipo di "documentazione bugiarda" piu'
comune (un endpoint rinominato, la doc mai toccata).
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RASPI_SCANNER_PY = REPO_ROOT / "raspi-scanner.py"
API_MD = REPO_ROOT / "API.md"

_ROUTE_RE = re.compile(r'@app\.route\(\s*"([^"]+)"')


def _real_routes():
    text = RASPI_SCANNER_PY.read_text()
    return sorted(set(_ROUTE_RE.findall(text)))


class TestApiDocsInSync(unittest.TestCase):
    def test_every_route_mentioned_in_api_md(self):
        api_md_text = API_MD.read_text()
        routes = _real_routes()
        self.assertTrue(routes, "nessuna route trovata in raspi-scanner.py: la regex e' rotta?")
        missing = [r for r in routes if r != "/" and r not in api_md_text]
        self.assertEqual(missing, [], f"route non documentate in API.md: {missing}")

    def test_api_md_does_not_reference_a_removed_route(self):
        """L'inverso: un path con "/api/" citato in API.md che non esiste
        piu' nel codice — es. un endpoint rinominato senza aggiornare la
        doc vecchia invece di scriverne una nuova."""
        # Normalizza qualunque placeholder Flask (<username>, <int:scan_id>,
        # ...) a un token comune su ENTRAMBI i lati: interessa solo la forma
        # del path, non il nome/tipo esatto del parametro documentato.
        def _normalize(path):
            return re.sub(r"/<[^>]+>", "/<param>", path)

        routes = {_normalize(r) for r in _real_routes()}
        api_md_text = API_MD.read_text()
        mentioned = set(re.findall(r'`(?:GET|POST|PUT|PATCH|DELETE) (/api/[^`\s?]+)', api_md_text))
        mentioned = {_normalize(m) for m in mentioned}
        stale = [m for m in mentioned if m not in routes]
        self.assertEqual(stale, [], f"API.md cita route che non esistono piu': {stale}")


if __name__ == "__main__":
    unittest.main()
