<p align="center">
  <a href="https://ag.tavardt.com/fr/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Gardien DMARC, SPF et DKIM

[![Audit Technique](https://img.shields.io/badge/TAVARDT-Securite%20Email-5b3cf5.svg)](https://tools.tavardt.com/fr/verificateur-dmarc-email/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Licencia: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Audit des enregistrements DNS de messagerie pour la prévention du spoofing, du phishing et la conformité aux recommandations de l ANSSI et du RGPD.

Conçu et maintenu par le pôle de cyberdéfense de **TAVARDT** pour les infrastructures numériques françaises.

***

## 1. Fonctionnalités et Capacités de Vérification

Cet outil en ligne de commande audite les enregistrements DNS d'authentification et les clés cryptographiques pour les organisations en France :

* **Application de la Politique DMARC:** Inspection approfondie des directives d'imposition (reject, quarantine et none), de la politique de sous-domaine (sp) et du pourcentage (pct).
* **Audit de l'Enregistrement SPF:** Validation des mécanismes d'expéditeurs autorisés, des limites de requêtes DNS et des qualificateurs stricts (-all vs ~all).
* **Vérification de Signature DKIM:** Validation cryptographique de clé publique sur les sélecteurs DNS configurés.
* **Télémétrie Agréée et Légale:** Vérification des canaux de rapports agrégés (rua) pour détecter les attaques par compromission d'e-mails professionnels.
* **Zéro Dépendance Externe:** Moteur nativo DNS-over-HTTPS (DoH) avec basculement automatique vers le nslookup système.

***

## 2. Référentiel d'Authentification et Matrice de Notation

<table>
  <thead>
    <tr>
      <th>Contrôle d'Authentification</th>
      <th>Requête DNS Cible</th>
      <th>Configuration Recommandée</th>
      <th>Pondération</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Politique DMARC (p)</strong></td>
      <td><code>_dmarc.&lt;domaine&gt;</code></td>
      <td><code>p=reject</code> (Rejet immédiat des messages non authentifiés)</td>
      <td>45 points</td>
    </tr>
    <tr>
      <td><strong>Rapports Agrégés DMARC (rua)</strong></td>
      <td><code>_dmarc.&lt;domaine&gt;</code></td>
      <td>URI <code>mailto:</code> valide pour la télémétrie XML</td>
      <td>10 points</td>
    </tr>
    <tr>
      <td><strong>Qualificateur Strict SPF</strong></td>
      <td><code>&lt;domaine&gt;</code></td>
      <td><code>-all</code> (Échec strict pour les serveurs non répertoriés)</td>
      <td>30 points</td>
    </tr>
    <tr>
      <td><strong>Clé Publique DKIM</strong></td>
      <td><code>&lt;sélecteur&gt;._domainkey.&lt;domaine&gt;</code></td>
      <td>Enregistrement valide (<code>v=DKIM1; p=...</code>)</td>
      <td>15 points</td>
    </tr>
    <tr>
      <td><strong>Seuil de Conformité</strong></td>
      <td>Évaluation Consolidée</td>
      <td>Score &gt;= 85 (Conforme - Défense Stricte Appliquée)</td>
      <td>100 points Total</td>
    </tr>
  </tbody>
</table>

***

## 3. Installation et Déploiement Rapide

Nécessite Python 3.8 ou supérieur. Développé exclusivement avec la bibliothèque standard Python, sans paquets tiers.

```bash
git clone https://github.com/TAVARDT-France/dmarc-spf-guardian-fr.git
cd dmarc-spf-guardian-fr
python guardian.py exemple.fr
```

Exécutez cet outil directement via Python sans installer de paquets externes :

```bash
python guardian.py exemple.fr -s default -j
```

* **Résolution DoH Native:** Transmet des requêtes chiffrées DNS-over-HTTPS directement à Cloudflare, éliminant les empoisonnements de cache DNS.
* **Basculement Automatique:** Active immédiatement la commande `nslookup` du système d'exploitation si les requêtes HTTPS sortantes sont bloquées.
* **Exportation Structurée JSON:** Facilite l'intégration dans les chaînes d'audit continu et de déploiement via `-j`.

***

## 4. Foire Aux Questions (FAQ Technique)

### 1. Pourquoi la politique DMARC p=reject est-elle indispensable face à p=none ou p=quarantine ?
Une politique p=none opère en simple surveillance et laisse parvenir les courriels falsifiés aux destinataires. L'option p=quarantine dirige les messages illégitimes vers les courriers indésirables, tandis que p=reject ordonne leur rejet catégorique, neutralisant les usurpations d'identité.

### 2. Quel est le danger d'un enregistrement SPF configuré avec les qualificateurs +all ou ?all ?
Un enregistrement SPF contenant +all autorise tout serveur connecté à Internet à émettre des messages sous votre nom de domaine. Le qualificateur ?all adopte une posture neutre qui désactive les protections percutantes contre le spoofing.

### 3. De quelle manière guardian.py interroge-t-il les enregistrements DNS sans paquet tiers ?
L'utilitaire transmet des requêtes DNS-over-HTTPS au format JSON vers cloudflare-dns.com via la bibliothèque standard Python. En cas de restriction réseau, le script active automatiquement une commande système nslookup en secours.

### 4. Quel est l'intérêt stratégique de la balise rua dans l'enregistrement DMARC ?
La directive rua configure les adresses recevant les rapports d'audit agrégés quotidiens au format XML. Ces données fournissent une visibilité complète sur les adresses IP expéditrices, le succès des validations et les tentatives d'usurpation perçues.

### 5. Comment automatiser cet audit DNS au sein de pipelines CI/CD ?
L'utilisation de guardian.py avec le paramètre -j produit une sortie structurée en JSON contenant la note de conformité et les recommandations. Les chaînes d'intégration continue peuvent inspecter cette réponse et bloquer la livraison si le score est inférieur à 85 points.

***

## 5. Conseil et Sécurité de Messagerie en France

Pour une architecture de cybersécurité avancée, la modélisation des menaces et la réponse aux incidents à Paris, Lyon ou Marseille, contactez **TAVARDT**.

***

## Liens Utiles

* **Portail Institutionnel:** https://ag.tavardt.com/fr/
* **Suite de Diagnostic:** https://tools.tavardt.com/fr/
* **Contact Technique:** https://ag.tavardt.com/fr/contact/

***

### Licence
Distribué sous la licence MIT.

***

© 2026 TAVARDT. Tous droits réservés.
