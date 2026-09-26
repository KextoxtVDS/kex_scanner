# KEX Scanner

Scanner de sécurité pour serveurs FiveM. Détecte et neutralise les backdoors cachées dans vos resources.

Né d'un incident réel : un serveur infecté par une chaîne de droppers à trois étages (stade 1 XOR-obfusqué dans un resource → stade 2 chargeur résilient → stade 3 exécution de code distant). Ce scanner porte les signatures de cette famille et atrappe tout ce qui lui ressemble, au boot et en continu.

## Ce qu'il détecte

- **Payloads obfusqués** — signature exacte `(function(){const <var>=<chiffre>;const <var>=[...]` + XOR + eval
- **Marqueurs C2 connus** — domaines et identifiants de la chaîne d'infection
- **Noms de fichiers homoglyphes** — le camouflage cyrillique des backdoors (`config.cсѕ.js` au lieu de `config.css.js`)
- **Fichiers non-ASCII déclarés dans les manifests** — un fxmanifest qui référence un fichier au nom exotique = alerte immédiate
- **Combos droppers** — `String.fromCharCode` + `eval(` dans un même fichier

## Ce qu'il fait

- **Au boot (+5 s)** : scan de toutes les resources démarrées, avant que le moindre timer de dropper ne se déclenche (+20 s typiquement)
- **Toutes les 30 minutes** : rescan complet en patrouille
- **À la demande** : commande `kexscan` en console (admin uniquement)
- **Quarantaine automatique** : resource stoppée immédiatement + tentative de suppression du fichier et de nettoyage du manifest
- **Console** : alertes rouges détaillées (resource, motif, fichier) ou `serveur propre : aucun payload trouvé`

## Installation

1. Copiez le dossier `kex_scanner` dans vos resources
2. `ensure kex_scanner` (ou placez-le dans une catégorie auto-ensurée)
3. Redémarrez — le scan démarre 5 secondes après le lancement

Aucune dépendance. Aucune configuration. Les exports Node sont verrouillés sur le resource lui-même (`GetInvokingResource == GetCurrentResourceName`) — aucun autre script ne peut s'en servir pour lire vos fichiers.

## Ajouter ses propres signatures

Les marqueurs vivent en tête de `server.lua` :

```lua
local MARKERS = {
    '9ns1.com',
    'zXeAHJJ',
    -- vos indicateurs ici
}
```

## Remarques

- La suppression de fichiers peut être refusée par la sandbox FiveM (écriture inter-ressource). Dans ce cas le resource est quand même **stoppé** avant tout fetch — la contamination ne se propage pas, il reste à supprimer le fichier à la main.
- Un fichier au nom exotique mais bénin (ex : `readme♥.txt`) peut être signalé — c'est voulu : un nom camouflé mérite un regard, même innocent.
- `monitor` (system resource officiel Cfx) et `_cfx_internal` sont sur liste blanche.

## Licence

MIT — faites-en ce que vous voulez, citez l'auteur si le cœur vous en dit.

---

**Kextoxt — Fusion**
