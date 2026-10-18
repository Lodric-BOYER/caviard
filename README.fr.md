# Caviard

**Masquage « fail-closed » des données personnelles et des secrets dans les traces et les logs d'agents IA.**

Les traces d'un agent contiennent ce que vos utilisateurs ont écrit : noms, emails,
numéros de téléphone, numéros de sécurité sociale, IBAN, clés d'API. Elles partent
ensuite vers un outil d'observabilité (Langfuse, Datadog, n'importe quel point d'entrée
OTLP), souvent hors de l'UE. Caviard les masque au moment de l'export, avant qu'elles ne
quittent votre application.

- **Identifiants français et européens, vérifiés** : NIR (Corse comprise), SIREN, SIRET,
  RPPS, IBAN, cartes bancaires et numéros de téléphone français, ainsi que les emails, les
  adresses IP, les clés d'API, les jetons Bearer, les JWT, les clés privées et les mots de
  passe. Les clés de contrôle (mod 97, Luhn) et les mots de contexte limitent les faux
  positifs.
- **Fail-closed** : un span qui ne peut pas être masqué est mis en quarantaine ou
  supprimé, jamais exporté en clair.
- **Des traces qui restent utiles** : noms de modèles, noms d'outils et nombres de tokens
  restent lisibles, les arguments JSON des outils sont masqués champ par champ, et les
  pseudonymes à clé (HMAC-SHA256) donnent le même jeton pour le même utilisateur : on peut
  toujours suivre une conversation.
- **Intégrations prêtes à l'emploi** : OpenTelemetry, Langfuse (SDK v5), LiteLLM, `logging`
  et structlog.
- **Audit hors ligne** des traces que vous avez déjà : `caviard audit export.jsonl -o rapport.html`.
- **Aucune dépendance** pour le cœur (bibliothèque standard uniquement). Licence Apache-2.0.

> **Statut : alpha (0.1).** La détection repose sur des motifs, des clés de contrôle et
> du contexte : les noms dans du texte libre ne sont pas détectés (pas de reconnaissance
> d'entités nommées), seulement les valeurs placées sous des champs comme
> `customer_name`. Lisez les [limites](#limites).

[English version](https://github.com/Lodric-BOYER/caviard/blob/main/README.md)

## Installation

```bash
pip install caviard                 # cœur et ligne de commande, aucune dépendance
pip install "caviard[otel]"         # exportateur OpenTelemetry
pip install "caviard[langfuse]"     # hook pour le SDK Langfuse v5
pip install "caviard[litellm]"      # callback LiteLLM
pip install "caviard[yaml]"         # politiques au format YAML
```

Python 3.11 à 3.14.

## Démarrage rapide

```python
import caviard

caviard.redact("Mon numéro de sécu est 1 85 03 75 112 345 94, mail jean.dupont@exemple.fr")
# 'Mon numéro de sécu est [FR_NIR], mail [EMAIL:rf4y3edldfcv]'
```

Par défaut, les emails, les numéros de téléphone et les adresses IP sont pseudonymisés.
Donnez une clé stable à Caviard, sinon les pseudonymes changent à chaque redémarrage :

```bash
caviard keygen                        # affiche une nouvelle clé aléatoire
export CAVIARD_HMAC_KEY="<cette clé>" # dans un gestionnaire de secrets, jamais dans le dépôt
```

### OpenTelemetry

Enveloppez votre exportateur : les spans sont masqués sur le thread d'export, hors du
chemin des requêtes.

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from caviard import Policy
from caviard.otel import RedactingSpanExporter

exporter = RedactingSpanExporter(OTLPSpanExporter(), Policy.load("caviard.toml"))
provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(exporter))
```

Les noms de spans, les attributs, les événements (messages d'exception), les liens, les
messages de statut et les attributs de ressource sont masqués. Les spans d'origine ne
sont jamais modifiés.

### Langfuse (SDK v5)

```python
from langfuse import Langfuse
from caviard.integrations.langfuse import mask_otel_spans

langfuse = Langfuse(mask_otel_spans=mask_otel_spans())
```

Chaque span est traité séparément : une erreur ne fait jamais perdre tout un lot. Ce hook
ne peut modifier que les attributs des spans ; pour couvrir aussi les noms, les événements
et les ressources, passez `span_exporter=RedactingSpanExporter(...)` à `Langfuse`.

### LiteLLM

```python
import litellm
from caviard.integrations.litellm import CaviardLogger

litellm.callbacks = [CaviardLogger(), *autres_callbacks]  # toujours en premier
```

Les messages, les métadonnées, les corps bruts des requêtes et des réponses, le payload
standard et les réponses (sync, async, streaming) sont masqués avant que les autres
callbacks ne les voient. Votre application garde la vraie réponse.

### logging et structlog

```python
import logging
from caviard.integrations.logging import install

logging.basicConfig(level=logging.INFO)
install()  # ajoute un RedactingFilter à chaque handler du logger racine
```

Avec structlog, ajoutez `caviard.integrations.logging.structlog_processor()` à la chaîne
de processeurs, après `format_exc_info` et avant le rendu.

## Auditer les traces existantes

```bash
caviard audit exports/ -o rapport.html --policy-out caviard.toml
```

`caviard audit` lit l'OTLP JSON écrit par l'exportateur fichier du Collector
OpenTelemetry, le JSON Lines, les tableaux JSON (un export Langfuse, par exemple) et le
texte, éventuellement compressés en gzip. Le rapport indique quelles données personnelles
vos traces contiennent et où (clés d'attributs, services, instrumentations), signale les
réglages risqués, propose une politique et liste les points à vérifier avec votre DPO. Il
ne contient que des comptages, des types et des noms d'attributs eux-mêmes masqués, jamais
une valeur analysée : vous pouvez donc le partager. `--examples N` ajoute des extraits
masqués ; le texte autour peut contenir des noms, gardez alors le rapport en interne.

## Politiques

Une politique est un fichier TOML, YAML ou JSON appliqué par-dessus un preset. Les listes
s'ajoutent à celles du preset ; les autres valeurs les remplacent.
`caviard policy check caviard.toml` affiche le résultat.

```toml
version = 1
preset = "standard"            # standard, strict, debug-local ou none

[entities]
FR_NIR = "mask"                # [FR_NIR]
EMAIL = "hash"                 # [EMAIL:rf4y3edldfcv], même email, même jeton
IBAN = "partial"               # [IBAN:...0189]
IP_ADDRESS = "keep"            # détecteur désactivé

[keys]                         # clés d'attributs, motifs glob
allow = ["app.request_id"]     # exportées telles quelles
mask = ["app.customer.*"]      # remplacées en entier : [REDACTED]
hash = ["app.user_id"]         # pseudonymisées en entier
drop = ["http.request.body"]   # supprimées

[json]
sensitive_fields = ["client_name"]  # champs JSON toujours remplacés

[pseudonym]
key_env = "CAVIARD_HMAC_KEY"   # ou key_file = "/run/secrets/caviard_key"
```

| Preset | Usage |
| --- | --- |
| `standard` (défaut) | Masque les identifiants et les secrets, pseudonymise emails, téléphones et adresses IP, garde lisibles les attributs de modèle et de consommation. |
| `strict` | Tout est masqué, rien n'est pseudonymisé ; un span qui échoue est supprimé. |
| `debug-local` | Tout est pseudonymisé sauf les secrets, pour déboguer en local. |
| `none` | Partir de zéro. |

Ordre de priorité des règles de clés : drop, mask, hash, allow. Les autres attributs
passent par les détecteurs.

## Ligne de commande

| Commande | Rôle |
| --- | --- |
| `caviard scan "texte"` | Montre ce qui serait masqué : types et positions, jamais les valeurs. |
| `caviard audit CHEMIN...` | Audit hors ligne de traces ou de logs exportés, avec rapport HTML ou JSON. |
| `caviard policy check FICHIER` | Valide une politique et affiche ses réglages effectifs. |
| `caviard bench` | Vitesse et taux de détection sur des traces synthétiques générées sur votre machine. |
| `caviard keygen` | Génère une clé de pseudonymisation. |

## Fonctionnement

1. **Détecter.** Des expressions régulières bornées trouvent les candidats, puis les clés
   de contrôle (mod 97 pour le NIR et l'IBAN, Luhn pour les cartes, le SIREN, le SIRET et
   le RPPS) et les mots de contexte les valident : un nombre à 9 chiffres n'est un SIREN
   que près de mots comme « SIREN » ou « société ». En cas de chevauchement, la détection
   la plus précise l'emporte.
2. **Remplacer.** Chaque type a une action : masquer, pseudonymiser (HMAC-SHA256 avec
   votre clé, après normalisation : `06 12 34 56 78` et `+33 6 12 34 56 78` donnent le même
   jeton), garder la fin ou conserver. Les chaînes JSON, y compris les arguments d'outils
   encodés deux fois, sont masquées champ par champ.
3. **Ne jamais fuir sur erreur.** En cas d'échec, les intégrations mettent
   l'enregistrement en quarantaine (seuls les attributs autorisés gardent leur valeur) ou
   le suppriment.

Six invariants sont chacun couverts par des tests : fail-closed ; idempotence (masquer
deux fois ne change rien) ; silence (aucune valeur analysée dans les erreurs, les logs ou
les rapports) ; temps borné (entrées hostiles de 1 Mo traitées en moins de 2,5 s, valeurs
au-delà de `max_chars` remplacées en entier) ; la clé de pseudonymisation n'apparaît
jamais en sortie ; lisibilité (noms de modèles, d'outils et nombres de tokens en clair).

## Limites

- **Pas de reconnaissance d'entités nommées.** Les noms, adresses postales ou données de
  santé dans du texte libre ne sont pas détectés ; ils ne sont remplacés que sous des
  champs comme `customer_name` ou `address`. Vous pouvez ajouter des détecteurs via le
  point d'entrée `caviard.detectors`.
- **Certains numéros exigent du contexte.** Les numéros de carte, de SIREN, de SIRET et de
  RPPS ne sont signalés que près de mots associés, pour éviter les faux positifs sur des
  numéros de commande ou de trace.
- **Les taux de détection viennent de données synthétiques** ; les vraies traces sont plus
  variées.
- **Les noms d'attributs sont exportés tels quels.** `caviard audit` prévient quand un nom
  contient une donnée personnelle.
- **LiteLLM :** pour les appels async qui échouent, les anciens callbacks texte comme
  `"langfuse"` dans `litellm.failure_callback` passent avant Caviard ; enregistrez vos
  loggers comme instances de `CustomLogger`. Les objets exception ne sont pas modifiés ;
  leur texte est masqué dans la traceback et le payload de log.
- **Vitesse :** quelques mégaoctets par seconde et par cœur. Masquez sur le thread
  d'export (`BatchSpanProcessor`), pas dans le chemin des requêtes.
- **Des données pseudonymisées restent des données personnelles** au sens du RGPD.
  Caviard réduit ce qui sort de vos systèmes ; il ne rend pas les traces anonymes.

## Sécurité

Signalez les vulnérabilités en privé, comme expliqué dans
[SECURITY.md](https://github.com/Lodric-BOYER/caviard/blob/main/SECURITY.md). Le modèle de
menaces est dans [THREAT_MODEL.md](https://github.com/Lodric-BOYER/caviard/blob/main/THREAT_MODEL.md).

## Développement

```bash
uv venv && uv pip install -e . --group dev
pytest
ruff check . && ruff format --check . && mypy
```

Les tests n'utilisent que des données synthétiques (Faker et identifiants générés),
jamais de vraies données personnelles.

## Licence

[Apache-2.0](https://github.com/Lodric-BOYER/caviard/blob/main/LICENSE)
