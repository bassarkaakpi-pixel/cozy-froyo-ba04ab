# Bassar Kàakpi – version finale à déposer sur Netlify

## Ce que contient le dossier
Le contenu de ce dossier, une fois dézippé, doit être déposé tel quel : index.html doit être à la racine.
Pages : accueil, histoire (B'Tchamb), marketplace, entreprises et vendeurs, abonnement résilier, boutique,
collections Heritage et tissu, inscription, publication d'annonce, mentions légales, conditions de vente, 404.

## Avant de déposer (à faire toi-même)
- [ ] Ouvrir chaque lien Stripe et PayPal sans payer : nom du produit, montant, essai d'un mois pour les abonnements.
      Liens produits : Stripe 249 € (3cIa), 349 € (8x25), 549 € (eVqc) · PayPal 249 € (8QS5), 349 € (RWUK), 549 € (F2V2).
      Abonnements : Stripe Vendeur (aFa8) et Premium (4gM5) · PayPal Vendeur (P-6P20) et Premium (P-17X2).
- [ ] Vérifier le plan PayPal Premium : 7,62 €/mois, avec un mois gratuit.
- [ ] Tester le parcours d'annulation chez Stripe (le portail client doit être activé) et chez PayPal, et corriger le texte de la page « Abonnement résilier » si les menus ont un autre nom.
- [ ] Tester l'e-mail de demande de résiliation (adresse bassarkaakpi@gmail.com).
- [ ] Faire relire par un juriste allemand : conditions de vente (section 9 et abonnements), mentions légales, page de résiliation, libellés des boutons.
- [ ] Confirmer le statut de petite entreprise (§ 19 UStG) avec ton Steuerberater.

## Procédure de dépôt
1. Note le déploiement actuellement publié dans Netlify (onglet Deploys) : c'est ton retour arrière.
2. Dézippe le fichier et glisse le **dossier** (celui qui contient index.html) dans le cadre « Drag and drop » de l'onglet Deploys.
3. Attends « Published ».
4. Ouvre bassarkaakpi.com dans une fenêtre privée et teste :
   - accueil, sélecteur FR / EN / DE ;
   - une collection : boutons de paiement, sans payer ;
   - la page marketplace et la page entreprises ;
   - la page 404 (adresse inexistante) ;
   - la page résilier ;
   - les liens WhatsApp.

## Retour arrière
Netlify, onglet Deploys, ancien déploiement, bouton « Publish deploy ».

## Limites connues
- Les abonnements ne sont pas activés automatiquement : tu valides chaque profil à la main après paiement.
- Les paiements entre membres (option B) ne sont pas en service : la page indique qu'ils sont en préparation.
- Les images « Illustration » ne sont pas des photos de produits livrés.
- Le formulaire envoie un PDF par WhatsApp : il faut un geste du visiteur.
