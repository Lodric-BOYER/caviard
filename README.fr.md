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
- **Fail-closed** : un span ou un log qui ne peut pas être masqué est mis en quarantaine
  ou supprimé, jamais exporté en clair.
- **Des traces qui restent utiles** : noms de modèles, noms d'outils et nombres de tokens
  restent lisibles, les arguments JSON des outils sont masqués champ par champ, et les
  pseudonymes à clé (HMAC-SHA256) donnent le même jeton pour le même utilisateur : on peut
  toujours suivre une conversation.
- **Intégrations prêtes à l'emploi** : OpenTelemetry (spans et logs), Langfuse (SDK v5),
  LiteLLM, `logging` et structlog.
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
# 'Mon numéro de sécu est [FR_NIR], mail [EMAIL:rf4y3edldfcv]'  (le jeton dépend de la clé)
```

Par défaut, les emails, les numéros de téléphone et les adresses IP sont pseudonymisés.
Donnez une clé stable à Caviard, sinon les pseudonymes changent à chaque redémarrage :

```bash
caviard keygen                        # affiche une nouvelle clé aléatoire
export CAVIARD_HMAC_KEY="<cette clé>" # dans un gestionnaire de secrets, jamais dans le dépôt
```

### OpenTelemetry

Enveloppez vos exportateurs : spans et logs sont masqués sur le thread d'export, hors du
chemin des requêtes. Les exemples utilisent les exportateurs OTLP/HTTP
(`pip install opentelemetry-exporter-otlp-proto-http`).

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from caviard.otel import RedactingSpanExporter

exporter = RedactingSpanExporter(OTLPSpanExporter())  # politique par défaut
provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(exporter))
```

Les noms de spans, les attributs, les événements (messages d'exception), les liens, les
messages de statut, l'état de trace (trace state), les attributs de ressource et ceux du
scope d'instrumentation sont masqués. Les spans d'origine ne sont jamais modifiés. Pour appliquer votre politique, passez-la en second argument :
`RedactingSpanExporter(OTLPSpanExporter(), Policy.load("caviard.toml"))`.

Caviard ne protège que les exportateurs qu'il enveloppe : enveloppez-les tous, y compris
un exportateur console ou un second backend ajouté plus tard, puis vérifiez un export
d'échantillon avec `caviard audit`.

Les instrumentations GenAI peuvent aussi envoyer prompts et réponses sous forme
d'événements de log : enveloppez aussi l'exportateur de logs (opentelemetry-sdk 1.39 ou
plus). Corps, attributs, noms d'événements et ressources sont masqués.

```python
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

from caviard.otel import RedactingLogExporter

exporter = RedactingLogExporter(OTLPLogExporter())
logger_provider = LoggerProvider()
logger_provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
```

### Langfuse (SDK v5)

```python
from langfuse import Langfuse
from caviard.integrations.langfuse import mask_otel_spans

langfuse = Langfuse(mask_otel_spans=mask_otel_spans())
```

Chaque span est traité séparément : une erreur ne fait jamais perdre tout un lot. Ce hook
ne peut modifier que les attributs des spans. Pour couvrir aussi les noms, les événements
et les ressources, donnez à Langfuse un exportateur enveloppé. Langfuse ne règle alors plus
lui-même l'adresse d'envoi ni les identifiants :

```python
import base64
import os

from langfuse import Langfuse
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

from caviard.otel import RedactingSpanExporter

base_url = os.environ.get("LANGFUSE_BASE_URL", "https://cloud.langfuse.com")
credentials = f"{os.environ['LANGFUSE_PUBLIC_KEY']}:{os.environ['LANGFUSE_SECRET_KEY']}"
exporter = OTLPSpanExporter(
    endpoint=f"{base_url}/api/public/otel/v1/traces",
    headers={
        "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
        "x-langfuse-ingestion-version": "4",
    },
)
langfuse = Langfuse(span_exporter=RedactingSpanExporter(exporter))
```

### LiteLLM

```python
import litellm
from caviard.integrations.litellm import CaviardLogger

litellm.callbacks = [CaviardLogger(), *autres_callbacks]  # toujours en premier
litellm.redact_messages_in_exceptions = True  # LiteLLM cite les messages dans ses erreurs
```

Les messages, les métadonnées, les corps bruts des requêtes et des réponses, le payload
standard et les réponses (sync, async, streaming) sont masqués avant que les callbacks de
journalisation ne les voient. En cas d'échec, les loggers reçoivent une copie de
l'exception, de la même classe, au texte masqué. Votre application garde la vraie réponse
et la vraie exception.

LiteLLM remet la requête brute aux méthodes `log_pre_api_call` et `log_post_api_call` de
chaque logger avant tout masquage possible, et le proxy LiteLLM remet requêtes et réponses
brutes à ses propres hooks. Caviard prévient une fois lorsqu'un logger enregistré
implémente ces deux méthodes. Pour les loggers OpenTelemetry de LiteLLM, exportez aussi à
travers Caviard, ce qui couvre chaque span quel que soit le hook :

```python
from litellm.integrations.opentelemetry import OpenTelemetry, OpenTelemetryConfig
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

from caviard.otel import RedactingSpanExporter

config = OpenTelemetryConfig(exporter=RedactingSpanExporter(OTLPSpanExporter()))
litellm.callbacks = [CaviardLogger(), OpenTelemetry(config=config)]
```

LiteLLM 1.87.4 ou plus est requis : les versions précédentes lancent en même temps les
loggers async et sync d'un appel en streaming, si bien qu'un logger pouvait lire les
données avant leur masquage. L'extra `litellm` exclut aussi la version 1.107.0,
compromise sur PyPI. Pour les appels async, le masquage s'exécute sur la boucle
d'événements (quelques millisecondes par appel).

Avec le proxy LiteLLM, référencez le callback dans la configuration du proxy :

```python
# custom_callbacks.py, à côté de config.yaml
from caviard.integrations.litellm import CaviardLogger

caviard_logger = CaviardLogger.from_policy("caviard.toml")
```

```yaml
litellm_settings:
  callbacks: custom_callbacks.caviard_logger  # en premier si vous listez d'autres loggers
  redact_messages_in_exceptions: true
```

### logging et structlog

```python
import logging
from caviard.integrations.logging import install

logging.basicConfig(level=logging.INFO)
install()  # ajoute un RedactingFilter à chaque handler du logger racine
```

Chaque argument d'un message est masqué séparément avant d'y être fusionné, les
dictionnaires champ par champ, puis le message fusionné, l'exception, la pile d'appels et
les champs `extra` (y compris les champs privés qui contiennent des données simples,
certains handlers les exportant). Avec structlog, ajoutez
`caviard.integrations.logging.structlog_processor()` à la chaîne de processeurs, après
`format_exc_info` et avant le rendu.

## Auditer les traces existantes

```bash
caviard audit exports/ -o rapport.html --policy-out proposition.toml
```

```text
caviard audit: 2 file(s), 7 record(s) (JSON objects 2, spans 5)
Personal data in 7 record(s) (100.0%).

  type            findings   records  policy
  EMAIL                 12         7  hash
  IBAN                   5         5  mask
  REDACTED               2         2  replace

  where                                                      values  rule   suggestion
  llm.input_messages.*.message.content [span]                   5/5  -      -
  exception.message [event exception]                           5/5  -      -
  customer_contact [record]                                     2/2  -      hash
  customer_name [record]                                        2/2  field  -
```

`caviard audit` lit l'OTLP JSON écrit par l'exportateur fichier du Collector
OpenTelemetry, le JSON Lines, les tableaux JSON (un export Langfuse, par exemple) et le
texte, éventuellement compressés en gzip. Les dossiers sont lus récursivement, et les
motifs comme `"exports/**/*.jsonl"` sont développés même quand le shell ne le fait pas
(PowerShell). Le rapport indique quelles données personnelles vos traces contiennent et où
(clés d'attributs, services, instrumentations), signale les réglages risqués, propose une
politique et liste les points à vérifier avec votre DPO. Il ne contient que des comptages,
des types et des noms eux-mêmes masqués (attributs, services, fichiers), jamais une valeur
analysée : vous pouvez donc le partager ; les messages d'erreur masquent aussi les noms de
fichiers. `--examples N` ajoute des extraits masqués ; le
texte autour peut contenir des noms, gardez alors le rapport en interne. `--json` affiche
le résumé en JSON, avec un `schema_version`. `--policy-out` écrit un nouveau fichier : il
n'en remplace jamais un existant sans `--force`, et aucune sortie ne remplace une entrée.
Avec `--check`, le code de sortie vaut 1 si des données personnelles sont trouvées, et aussi
si des valeurs n'ont pas pu être analysées (trop grandes, binaires) : non analysé ne veut
pas dire propre. Un document JSON est lu d'un bloc jusqu'à 64 Mo ; exportez les plus gros
en JSON Lines. Les lignes de plus de 16 Mo sont ignorées et signalées.

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
sensitive_fields = ["numero_dossier"]  # noms de champs dont la valeur est toujours remplacée

[pseudonym]
key_env = "CAVIARD_HMAC_KEY"   # ou key_file = "/run/secrets/caviard_key"
```

| Preset | Usage |
| --- | --- |
| `standard` (défaut) | Masque les identifiants et les secrets, pseudonymise emails, téléphones et adresses IP, garde lisibles les attributs de modèle et de consommation. |
| `strict` | Tout est masqué, rien n'est pseudonymisé ; un span qui échoue est supprimé. |
| `debug-local` | Chaque identifiant détecté est pseudonymisé (secrets et JWT restent masqués), pour déboguer en local. |
| `none` | Partir de zéro. |

Ordre de priorité des règles de clés : drop, mask, hash, allow. Les autres attributs
passent par les détecteurs.

| Réglage | Défaut (`standard`) | Rôle |
| --- | --- | --- |
| `version` | obligatoire | Version du format de politique : `1`. |
| `preset` | `"standard"` | Preset de base : `standard`, `strict`, `debug-local` ou `none`. |
| `on_error` | `"quarantine"` | En cas d'échec du masquage : `quarantine` (seuls les attributs autorisés gardent leur valeur) ou `drop`. |
| `max_chars` | `200000` | Les valeurs plus longues sont remplacées en entier par `[TOO_LARGE]` (de 1 000 à 100 000 000). |
| `default_action` | `"mask"` | Action des types sans règle dans `[entities]` : `mask`, `hash` ou `partial`. |
| `plugins` | `true` | Charge les détecteurs déclarés sous le point d'entrée `caviard.detectors`. |
| `[entities]` | emails, téléphones et adresses IP en `hash` | Par type : une action (`mask`, `hash`, `partial`, `keep` pour désactiver le détecteur) ou une table avec `action`, `min_score` (de 0 à 1) et `keep_last` (de 1 à 8, pour `partial`). |
| `[keys]` | attributs de modèle, de consommation et de service autorisés ; en-têtes HTTP secrets capturés masqués, dans les deux graphies (`x-api-key`, `x_api_key`) | Listes `allow`, `mask`, `hash` et `drop` de motifs de clés d'attributs (`*` couvre n'importe quel texte, points compris ; sensible à la casse). |
| `[json] max_depth` | `4` | Niveaux de JSON encodé dans des chaînes qui sont décodés et parcourus (de 0 à 16). Au-delà, un document JSON est remplacé en entier ; `0` lit le JSON comme du texte. |
| `[json] sensitive_fields` | noms, emails, téléphones, adresses, dates de naissance, IBAN, NIR, données de carte, mots de passe, secrets, jetons, clés d'API, cookies, noms composés compris (`billing_address`, `db_password`) | Noms de champs dont la valeur est toujours remplacée, en JSON, dans les valeurs Python et dans le texte (`customer_name='...'`, `adresse : ...`). Casse, accents et séparateurs sont ignorés : `Prénom`, `prenom` et `pré-nom` sont le même nom. `*` couvre n'importe quel texte : `"*_dossier"`. |
| `[pseudonym] key_env` | `"CAVIARD_HMAC_KEY"` | Variable d'environnement qui contient la clé. |
| `[pseudonym] key_file` | aucun | Fichier qui contient la clé ; prioritaire sur `key_env` s'il est renseigné. |
| `[pseudonym] length` | `12` | Longueur des jetons (de 8 à 32). |

Changer de clé de pseudonymisation change tous les jetons : les valeurs pseudonymisées avec
l'ancienne clé ne peuvent plus être reliées aux nouvelles. Gardez l'ancienne clé tant que
vous devez corréler des traces passées, et n'utilisez jamais la même clé pour des
environnements qui doivent rester impossibles à relier.

## Ligne de commande

| Commande | Rôle |
| --- | --- |
| `caviard scan "texte"` | Montre ce qui serait masqué : types et positions, jamais les valeurs. |
| `caviard audit CHEMIN...` | Audit hors ligne de traces ou de logs exportés, avec rapport HTML ou JSON. |
| `caviard policy check FICHIER` | Valide une politique et affiche ses réglages effectifs. |
| `caviard bench` | Vitesse et taux de détection par type sur des traces synthétiques générées sur votre machine. |
| `caviard keygen` | Génère une clé de pseudonymisation. |

## Fonctionnement

1. **Détecter.** Des expressions régulières bornées trouvent les candidats, puis les clés
   de contrôle (mod 97 pour le NIR et l'IBAN, Luhn pour les cartes, le SIREN, le SIRET et
   le RPPS) et les mots de contexte les valident : un nombre à 9 chiffres n'est un SIREN
   que près de mots comme « SIREN » ou « société ». En cas de chevauchement, la détection
   la plus précise l'emporte. Dans du texte, les valeurs écrites après un nom de champ
   sensible sont trouvées aussi (`customer_name='...'`, `adresse : ...`, logfmt,
   paramètres d'URL, repr Python, JSON tronqué), en entier : jusqu'au champ suivant, à une
   parenthèse fermante ou à la fin de la ligne, y compris dans la valeur d'autres champs
   (`url=...?token=...`). Les objets JSON ou dictionnaires Python cités dans un message
   sont lus champ par champ. Les caractères déguisés ne cachent rien : caractères
   invisibles (espace sans chasse, trait d'union conditionnel), chiffres pleine chasse,
   espaces insécables, tirets et accents séparés de leur lettre sont normalisés avant la
   détection, et les caractères échappés (`\u00e9` en JSON, `\xe9` dans des octets
   Python) ne cachent pas une adresse email.
2. **Remplacer.** Chaque type a une action : masquer, pseudonymiser (HMAC-SHA256 avec
   votre clé, après normalisation : `06 12 34 56 78` et `+33 6 12 34 56 78` donnent le même
   jeton), garder la fin ou conserver. Les chaînes JSON, y compris les arguments d'outils
   encodés deux fois, sont masquées champ par champ, clés comprises. Ce qui ne peut pas
   être inspecté est remplacé en entier : valeurs d'autres types (octets, objets), JSON
   imbriqué au-delà de 64 niveaux, trop profond pour être lu ou encodé plus de
   `json.max_depth` fois. Les jetons de masquage déjà présents dans un texte sont gardés,
   mais ne protègent jamais une valeur qui leur est collée (`[SECRET]hunter2`).
3. **Ne jamais fuir sur erreur.** En cas d'échec, les intégrations mettent
   l'enregistrement en quarantaine (seuls les attributs autorisés gardent leur valeur) ou
   le suppriment. Un texte qui contient plus de 10 000 correspondances candidates est
   remplacé en entier, ce qui borne le temps passé sur les entrées hostiles ; de même pour
   un texte construit pour que son masquage ne se stabilise jamais.

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
- **Certains formats ne sont pas détectés :** numéros internationaux sans `+`
  (`33612345678`), NIR coupé sur deux lignes, valeurs encodées en base64.
- **Les noms de champs sont lus largement.** Une valeur écrite après un nom sensible est
  remplacée aussi dans de la prose (`email : voir plus bas`) et dans du code
  (`token = make_token()`) ; les booléens, valeurs nulles et annotations de type
  (`password: str`) sont laissés tels quels.
- **Les taux de détection viennent de données synthétiques.** `caviard bench` les donne
  par type, dans les formats qu'écrit son générateur ; les vraies traces sont plus variées.
- **Les noms d'attributs sont exportés tels quels** (les clés à l'intérieur des valeurs
  sont masquées). `caviard audit` prévient quand un nom contient une donnée personnelle.
- **LiteLLM :** pour les appels async qui échouent, les anciens callbacks texte comme
  `"langfuse"` dans `litellm.failure_callback` passent avant Caviard ; enregistrez vos
  loggers comme instances de `CustomLogger`. La copie d'exception remise aux loggers n'a
  pas de frames (elles contiennent les variables locales) : sa pile d'appels est jointe
  sous forme de texte masqué. Les loggers qui implémentent `log_pre_api_call` ou
  `log_post_api_call` reçoivent la requête brute (Caviard prévient). Pour les appels async
  en streaming, LiteLLM écrit la réponse assemblée dans l'état de logging après le passage
  des loggers async, et Caviard la masque de nouveau quelques millisecondes plus tard : un
  logger qui garde `kwargs` pour le lire plus tard doit copier ce dont il a besoin dans
  son callback.
- **Vitesse :** environ 1 à 3 Mo/s par cœur, moins sur des textes courts riches en
  identifiants (`caviard bench` la mesure sur votre machine). Masquez sur le thread
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
