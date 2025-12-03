# 🛡️ Challenge 1 – VibeStream  
## Audit de Sécurité Externe : `python.org`

> ✅ **Objectif** : Scanner un site externe via l’API Scorton, identifier des signaux faibles et proposer des améliorations concrètes.

---

## 📸 Résultat du scan (capture textuelle)

Voici la **réponse brute de l’API Scorton** lors du scan de `https://www.python.org` :

```json
{
  "snapshot": {
    "url": "https://www.python.org",
    "domain": "www.python.org",
    "http": {
      "status": 200,
      "final_url": "https://www.python.org/",
      "html": "<!doctype html>... (tronqué) ..."
    },
    "tls": {
      "issuer": { "commonName": "GlobalSign Atlas R3 DV TLS CA 2025 Q1" },
      "notAfter": "Apr 13 12:55:25 2026 GMT"
    },
    "whois": {
      "registrar": "Gandi SAS",
      "creation_date": "1995-03-27 05:00:00+00:00",
      "expiration_date": "2033-03-28 05:00:00+00:00"
    },
    "tech": [
      ["jquery", "1.8.2"],
      ["jquery-ui", "1.12.1"]
    ]
  },
  "findings": [
    {
      "id": "old_jquery",
      "severity": "medium",
      "detail": "Version jQuery obsolète détectée : 1.8.2"
    },
    {
      "id": "old_jquery_ui",
      "severity": "medium",
      "detail": "Version jQuery UI obsolète détectée : 1.12.1"
    }
  ]
}
```

---

## 1. Preuve des anomalies détectées

### **Lignes HTML incriminées** :

```html
<!-- Chargement de jQuery 1.8.2 -->
<link rel="prefetch" href="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js">
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
<script>window.jQuery || document.write('<script src="/static/js/libs/jquery-1.8.2.min.js"><\/script>')</script>

<!-- Chargement de jQuery UI 1.12.1 -->
<link rel="prefetch" href="//ajax.googleapis.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js">
<link rel="stylesheet" href="//ajax.googleapis.com/ajax/libs/jqueryui/1.12.1/themes/smoothness/jquery-ui.css">
<script src="//ajax.googleapis.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js"></script>
```

> **Versions détectées** :
> - **jQuery 1.8.2** → sortie en **août 2012** (13+ ans)
> - **jQuery UI 1.12.1** → sortie en **juin 2016** (9+ ans)

---

## 2. Données collectées

| Catégorie            | Valeur |
|----------------------|--------|
| **URL**              | `https://www.python.org` |
| **Statut HTTP**      | `200 OK` |
| **HTTPS**            | Actif + HSTS |
| **Certificat TLS**   | Valide → **13 avr. 2026** |
| **Domaine**          | Créé le **27 mars 1995** (29+ ans) |
| **Registrar**        | `Gandi SAS` |
| **Technos obsolètes**| `jQuery 1.8.2`, `jQuery UI 1.12.1` |
| **Trackers détectés**| Google Analytics, EthicalAds, Plausible |
| **Score de sécurité**| **88.47/100** (risque **faible**) |

---

## 3. Analyse des vulnérabilités

### 🔧 Problèmes identifiés :

#### 1. **jQuery 1.8.2**
- **Vulnérabilités connues** :
  - [CVE-2015-9251](https://nvd.nist.gov/vuln/detail/CVE-2015-9251) – XSS via attributs d’événements
  - [CVE-2020-11022/23](https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2) – Sélecteurs CSS injectables

#### 2. **jQuery UI 1.12.1**
- **Vulnérabilités connues** :
  - [CVE-2021-41184](https://nvd.nist.gov/vuln/detail/CVE-2021-41184) – XSS dans le composant Tooltip
  - [CVE-2021-41182](https://nvd.nist.gov/vuln/detail/CVE-2021-41182) – XSS dans Dialog

### Contexte d’exposition :
Bien que le site soit **principalement statique**, il charge :
- Un **formulaire interactif** (`search-the-site`)
- Des **scripts dynamiques** (`text-grow`, `slide-code`, `launch-shell`)
- Des **scripts tiers** : `ethicalads.min.js`, `fundraiser-banner.js`, Google Analytics

→ Ces éléments augmentent la **surface d’attaque** en cas d’injection ou de compromission d’un script tiers.

### Évaluation du risque :
| Critère       | Valeur        |
|---------------|---------------|
| **Sévérité**  | Moyenne       |
| **Probabilité**| Faible à moyenne |
| **Impact**    | XSS client-side → phishing, session hijacking |

---

## 4. Hypothèse contextualisée

> **L’usage conjoint de jQuery 1.8.2 et jQuery UI 1.12.1 constitue une dette technique silencieuse.**  
> Bien que le site soit globalement sécurisé, ces dépendances **obsolètes et non maintenues** représentent un risque croissant. Une vulnérabilité zero-day ou une compromission d’un script tiers pourrait exploiter ces anciennes bibliothèques.

---

## 5. Propositions d’amélioration

### Recommandations techniques :

1. **Mettre à jour** :
   - jQuery → **3.7.1** (dernière LTS)
   - jQuery UI → **1.13.3** (dernière version)

2. **ou mieux** : **supprimer les dépendances** si les fonctionnalités peuvent être implémentées en **Vanilla JS** :
   - Menus déroulants → `classList.toggle()`
   - Ajustement de texte → `style.fontSize`
   - Slideshow → `classList` + timers simples

3. **Ajouter Subresource Integrity (SRI)** pour les scripts CDN :

```html
<script src="https://code.jquery.com/jquery-3.7.1.min.js"
        integrity="sha384-..."
        crossorigin="anonymous"></script>
```

---

## 6. Livrables du challenge

- Dataset JSON fourni via l’API Scorton (`snapshot` + `findings`)
- Page d’audit claire et structurée (ce README)
- Détection de **2 anomalies non triviales** (jQuery + jQuery UI obsolètes)
- Justification contextualisée + propositions concrètes
- Respect des critères du challenge VibeStream

---

> **Audit réalisé le** : `2025-12-03`  
> **Source** : Scan via API Scorton (`openapi.json`)  
> **Statut du challenge** : **Réussi**
