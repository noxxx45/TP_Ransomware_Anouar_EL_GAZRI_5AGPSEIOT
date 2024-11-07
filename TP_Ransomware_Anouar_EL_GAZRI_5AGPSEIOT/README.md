Anouar EL GAZRI 5A IoT

CHIFFREMENT :

1) L'algorithme qui est utilisé ici se nomme "XOR cipher" ou encore "chiffrement XOR" en français. L'algorithme utilise un XOR pour effectuer le chiffrement et le déchiffrement. Il est symétrique, on fait un XOR pour chiffrer et déchiffrer.
Cet algorithme de chiffrement n'est pas très robuste car premièrement il se base sur une répétition de clef. La clef peut donc être courte si celle-ci est répétée de nombreuses fois, cela peut permettre à l'attaquant de trouver des motifs et d'essayer de trouver la clef plus facilement.

GÉNÉRATION DES SECRETS :

2) PBKDF2 est une fonction de dérivation clé qui est coûteuse en calcul. Il est souvent utilisé avec d'autres algorithmes, tel que SHA-256 pour créer une fonction de hachage de mot de passe plus puissante. Le HMAC est utilisé pour faire de l'athentification et plutôt vérifier l'intégrité et l'authenticité du message, PBKDF2 est plus performant dans ce cadre car il va permettre de générer des clef résistantes à des attaques brutes forces. On n'effectue pas le hashage directement du sel et de la clef mais on utilise plutôt le PBKDF2 car PBKDF2 permet de ralentir le processus de hashage en répétant la fonction de hashage plusieurs fois comme dans notre cas 48000 fois. Cela permettra d'éviter ou de réduire des attaques par brutes forces par exemple. 

SETUP : 

3) Il est préférable de vérifier qu'un fichier token.bin est déjà présent ou non car si un fichier token est déjà présent dans le répertoire, alors si on ajoute un deuxième fichier token.bin, il va venir écraser celui qui était déjà présent. Or on ne veut pas ça car le fichier token.bin contient le token d’authentification qui est utilisé pour déchiffrer les fichiers. Cela pourrait rendre impossible le déchiffrement des fichiers étant donné que la clef sera perdue. 


ENCRYPT : 

Pour pouvoir tester le chiffrement des fichiers (txt) à l'aide du ransomware, on lance dans un premier dans un premier terminal le script "run_cnc.sh" puis dans un second on lance "run_ransomware.sh". On a bien le message qui s'affiche chez la victime. Pour ensuite vérifier si les fichiers ont bien étés chiffrés chez la victime, on lance dans un troisième terminal "exec_target.sh" puis on va dans le dossier "ransomware" qui est dans "root", puis on lance le script python à l'aide de la commande suivante "python3 ransomware.py". A l'aide d'un "cat file.txt", on peut voir que le fichier est chiffré.

VÉRIFIER ET UTILISER LA CLEF : 

4) Pour vérifier si la clef est la bonne, il ne suffit pas de vérifier simplement le champs de la clef, c'est-à-dire si le champs de la clef utilisé pour le chiffrement du fichier est similaire au champs de la clef utilisé pour le déchiffrement. Il faut qu'on vérifie que la clef fournie pour le déchiffrement correspond à la clé dérivée à partir du SALT (et du TOKEN) chargés.


BONUS : 

Voici les fonctionnalités et les réponses aux questions BONUS que j'ai pu faire.

Packer : 

B4) Il faut utiliser la commande suivante "pyinstaller --onefile ransomware.py" pour faire un executable autonome.
Une fois la commande lancé, voici ce qu'on obtient sur le terminal à la dernière ligne : 
"8791 INFO: Building EXE from EXE-00.toc completed successfully."
Le "--onefile" permet de rassembler tous les fichiers en un seul binaire exécutable. La fonctionnalité "--noconsole" pourrait être intéressante à rajouter dans la ligne de commande, mais dans notre cadre d'utilisation, on veut que la victime voit s'afficher dans un terminal le message de HACK mais sinon l'utilisation de l'option "--noconsole" dans la commande permettrait à l'executable de s'éxuter en arrière plan sans que la victime l'aperçoive sur un terminal

B5) Le fichier binaire qui a été créé se trouve dans le répertoire "dist", plus précisément dans le répertoire "sources" du projet puis dans le répertoire "dist" : "/TD/sources/dist"
À l'intérieur de répertoire on trouve notre fichier binaire intitulé "ransomware".

MOYEN DE PRESSION : 

- Bloquer le terminal
- Ajouter un compte à rebours

Pour faire la fonctionnalité "bloquer le terminal", j'ai utilisé dans le fichier ransomware.py la bibliothèque signal pour intercepter les signaux.
Les signaux SIGINT et SIGTERM sont bloqués, ce qui ne permet pas à la victime de faire un "Ctrl + C" pour stopper le malware.

Pour la fonctionnalité "ajouter un compte à rebours", j'ai écris une fonction "countdown" qui se lance en parralèle des autres actions sur un autre thread.
Une fois le temps écoulé (5min dans le code par exemple), les fichiers txt chiffrés sont supprimés.

ANALYSE CRITIQUE : 

Pour ma part, ce TP a été très intéressant. J'ai passé beaucoup de temps sur les 2 premières parties du TP surtout dans la partie test du chiffrement des fichiers txt à l'aide du ransomware dans l'environnement Docker. D'autres fonctionnalités peuvent être implémentés (leak_files...) pour améliorer le ransomware, on pourrait par exemple essayer de faire du phishing avec ce ransomware. Par exemple récupérer des id de connexion par phishing puis essayer d'avoir accès au PC de la victime et de faire tourner le ransomware. Autre méthode, on pourrait par exemple mettre ce ransomware dans un fichier zip sous forme d'un nom différent afin que la victime ouvre ce fichier et pense que c'est un fichier normal qui lui a été transmise par mail du type "agenda2024". Une fois ouvert, le ransomware tournera sur la machine de la victime et fera son boulot.