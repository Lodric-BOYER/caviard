# Caviard : règles du projet pour Claude Code

Caviard masque les données personnelles et les secrets dans les traces et les logs
d'agents IA, au moment de l'export. La conception complète (privée, non versionnée)
est dans `notes/conception.md` quand le fichier est présent.

## Invariants (non négociables, chacun couvert par un test)
- I1 fail-closed : aucune valeur non traitée n'est exportée ; en cas d'erreur, quarantaine puis abandon.
- I2 idempotence : masquer deux fois donne le même résultat que masquer une fois.
- I3 silence : aucune valeur brute dans les messages d'erreur, les logs ou les rapports.
- I4 temps borné : regex à quantificateurs bornés, pré-filtre obligatoire, plafond de taille, test sur 1 Mo.
- I5 corrélation : même clé HMAC, même pseudonyme ; la clé n'apparaît jamais dans les sorties.
- I6 lisibilité : noms d'outils, modèles et compteurs de tokens restent en clair.

## Règles de code
- Noyau (`src/caviard/core`) : bibliothèque standard uniquement, aucune dépendance.
- Paquets tiers importés seulement dans `caviard.otel` et `caviard.integrations.*`.
- Aucune donnée réelle dans le dépôt : Faker `fr_FR` et gabarits synthétiques seulement.
- Tout changement arrive avec son test ; pytest, ruff et mypy doivent passer.
- Commentaires concis, par blocs, pas ligne à ligne.
- Une étape à la fois : la suivante ne commence pas tant que les tests ne sont pas verts.

## Commandes
- Installer : `uv venv && uv pip install -e . --group dev` (ou `pip install -e . --group dev`, pip 25.1 ou plus)
- Tester : `pytest`
- Vérifier : `ruff check . && ruff format --check . && mypy`
