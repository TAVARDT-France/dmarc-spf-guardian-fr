# Gardien DMARC, SPF et DKIM

[![Licence : MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Audit Technique](https://img.shields.io/badge/TAVARDT-Securite%20Email-5b3cf5.svg)](https://tools.tavardt.com/fr/verificateur-dmarc-email/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

Audit des enregistrements DNS de messagerie pour la prévention du spoofing, du phishing et la conformité aux recommandations de l ANSSI et du RGPD.

Developpe et maintenu par le departement de cybersecurite et d infrastructure de **TAVARDT**.

***

## Fonctionnalites et Verifications

* **Validation de la Politique DMARC**: Examen des directives de blocage (reject, quarantine et none), alignement des sous-domaines (sp) et pourcentage d application (pct).
* **Audit des Enregistrements SPF**: Verification des mecanismes autorises, respect de la limite des requetes DNS et qualificateurs stricts (-all vs ~all).
* **Controle des Signatures DKIM**: Validation des cles publiques declarees sur les selecteurs DNS designes.
* **Rapports Automatises**: Verification de la presence des adresses de rapportage agreges et forensiques (rua et ruf).
* **Conformite Normative**: Conforme aux exigences du Guide de Sécurité de la Messagerie de l ANSSI et Conformité RGPD (CNIL).

***

## Installation et Utilisation

Necessite uniquement Python 3.8 ou superieur, reposant exclusivement sur la bibliotheque standard sans dependance externe.

```bash
git clone https://github.com/TAVARDT-France/dmarc-spf-guardian-fr.git
cd dmarc-spf-guardian-fr
python guardian.py entreprise.fr
```

Pour verifier un selecteur DKIM particulier ou exporter les resultats en JSON:

```bash
python guardian.py entreprise.fr -selector mail -json
```

***

## Diagnostic Web en Ligne

Pour des analyses poussees et des audits d infrastructure en continu, consultez l outil officiel:

* **Verificateur DMARC et Securite Email**
* **[Portail Entreprise TAVARDT](https://ag.tavardt.com/fr/)**

***

## Conseil et Expertise Technique

Pour vos projets d infrastructure, de cybersecurite et de conformite en France, sollicitez les ingenieurs de **TAVARDT**.

***

## Liens Utiles

* **Portail Entreprise:** https://ag.tavardt.com/fr/
* **Suite de Diagnostic:** https://tools.tavardt.com/fr/
* **Contact Technique:** https://ag.tavardt.com/fr/contact/

***

### Licence
Distribué sous la licence MIT. Consultez le fichier [LICENSE](LICENSE) pour plus de détails.

***

© 2026 TAVARDT. Tous droits réservés.
