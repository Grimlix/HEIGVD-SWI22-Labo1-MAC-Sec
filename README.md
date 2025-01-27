Nicolas Hungerbühler & Lucas Gianinetti
___

# Sécurité des réseaux sans fil

## Laboratoire 802.11 sécurité MAC

__A faire en équipes de deux personnes__


1. [Deauthentication attack](#1-deauthentication-attack)
2. [Fake channel evil tween attack](#2-fake-channel-evil-tween-attack)
3. [SSID Flood attack](#3-ssid-flood-attack)
4. [Probe Request Evil Twin Attack](#4-probe-request-evil-twin-attack)
5. [Détection de clients et réseaux](#5-d%c3%a9tection-de-clients-et-r%c3%a9seaux)
6. [Hidden SSID reveal](#6-hidden-ssid-reveal)
7. [Livrables](#livrables)
8. [Échéance](#%c3%89ch%c3%a9ance)



### Pour cette partie pratique, vous devez être capable de :

*	Détecter si un certain client WiFi se trouve à proximité
*	Obtenir une liste des SSIDs annoncés par les clients WiFi présents

Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy et la suite aircrack pour vos manipulations. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). __Si vous utilisez une VM, il vous faudra une interface WiFi usb, disponible sur demande__.

Des routers sans-fils sont aussi disponibles sur demande si vous en avez besoin (peut être utile pour l'exercices challenge 6).

__ATTENTION :__ Pour vos manipulations, il pourrait être important de bien fixer le canal lors de vos captures et/ou vos injections (à vous de déterminer si ceci est nécessaire pour les manipulations suivantes ou pas). Une méthode pour fixer le canal a déjà été proposée dans un laboratoire précédent.

## Quelques pistes utiles avant de commencer :

- Si vous devez capturer et injecter du trafic, il faudra configurer votre interface 802.11 en mode monitor.
- Python a un mode interactif très utile pour le développement. Il suffit de l'invoquer avec la commande ```python```. Ensuite, vous pouvez importer Scapy ou tout autre module nécessaire. En fait, vous pouvez même exécuter tout le script fourni en mode interactif !
- Scapy fonctionne aussi en mode interactif en invoquant la commande ```scapy```.  
- Dans le mode interactif, « nom de variable + <enter> » vous retourne le contenu de la variable.
- Pour visualiser en détail une trame avec Scapy en mode interactif, on utilise la fonction ```show()```. Par exemple, si vous chargez votre trame dans une variable nommée ```beacon```, vous pouvez visualiser tous ces champs et ses valeurs avec la commande ```beacon.show()```. Utilisez cette commande pour connaître les champs disponibles et les formats de chaque champ.
- Vous pouvez normalement désactiver la randomisation d'adresses MAC de vos dispositifs. Cela peut être utile pour tester le bon fonctionnement de certains de vos scripts. [Ce lien](https://www.howtogeek.com/722653/how-to-disable-random-wi-fi-mac-address-on-android/) vous propose une manière de le faire pour iOS et Android. 

## Partie 1 - beacons, authenfication

### 1. Deauthentication attack

Une STA ou un AP peuvent envoyer une trame de déauthentification pour mettre fin à une connexion.

Les trames de déauthentification sont des trames de management, donc de type 0, avec un sous-type 12 (0x0c). Voici le format de la trame de déauthentification :

![Trame de déauthentification](images/deauth.png)

Le corps de la trame (Frame body) contient, entre autres, un champ de deux octets appelé "Reason Code". Le but de ce champ est d'informer la raison de la déauthentification. Voici toutes les valeurs possibles pour le Reason Code :

| Code | Explication 802.11                                                                                                                                     |
|------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0    | Reserved                                                                                                                                              |
| 1    | Unspecified reason                                                                                                                                    |
| 2    | Previous authentication no longer valid                                                                                                               |
| 3    | station is leaving (or has left) IBSS or ESS                                                                                                          |
| 4    | Disassociated due to inactivity                                                                                                                       |
| 5    | Disassociated because AP is unable to handle all currently associated stations                                                                        |
| 6    | Class 2 frame received from nonauthenticated station                                                                                                  |
| 7    | Class 3 frame received from nonassociated station                                                                                                     |
| 8    | Disassociated because sending station is leaving (or has left) BSS                                                                                    |
| 9    | Station requesting (re)association is not authenticated with responding station                                                                       |
| 10   | Disassociated because the information in the Power Capability element is unacceptable                                                                 |
| 11   | Disassociated because the information in the Supported Channels element is unacceptable                                                               |
| 12   | Reserved                                                                                                                                              |
| 13   | Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 7 |
| 14   | Message integrity code (MIC) failure                                                                                                                                              |
| 15   | 4-Way Handshake timeout                                                                                                                                              |
| 16   | Group Key Handshake timeout                                                                                                                                              |
| 17   | Information element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame                                                                                                                                              |
| 18   | Invalid group cipher                                                                                                                                              |
| 19   | Invalid pairwise cipher                                                                                                                                              |
| 20   | Invalid AKMP                                                                                                                                              |
| 21   | Unsupported RSN information element version                                                                                                                                              |
| 22   | Invalid RSN information element capabilities                                                                                                                                              |
| 23   | IEEE 802.1X authentication failed                                                                                                                                              |
| 24   | Cipher suite rejected because of the security policy                                                                                                                                              |
| 25-31 | Reserved                                                                                                                                              |
| 32 | Disassociated for unspecified, QoS-related reason                                                                                                                                              |
| 33 | Disassociated because QAP lacks sufficient bandwidth for this QSTA                                                                                                                                              |
| 34 | Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions                                                                                                                                              |
| 35 | Disassociated because QSTA is transmitting outside the limits of its TXOPs                                                                                                                                              |
| 36 | Requested from peer QSTA as the QSTA is leaving the QBSS (or resetting)                                                                                                                                              |
| 37 | Requested from peer QSTA as it does not want to use the mechanism                                                                                                                                              |
| 38 | Requested from peer QSTA as the QSTA received frames using the mechanism for which a setup is required                                                                                                                                              |
| 39 | Requested from peer QSTA due to timeout                                                                                                                                              |
| 40 | Peer QSTA does not support the requested cipher suite                                                                                                                                              |
| 46-65535 | Reserved                                                                                                                                              |

a) Utiliser la fonction de déauthentification de la suite aircrack, capturer les échanges et identifier le Reason code et son interpretation.

Voici la commande utilisée pour déauthentifier un client d'un Access Point spécifique :

```aireplay-ng -0 1 -a <MAC_ACCESS_POINT> -c <MAC_CIBLE> <INTERFACE NAME>```

-  -0 veut dire deauthentification
-  1 c'est le nombre de déhautentification qu'on lance
-  -a pour l'adresse MAC de l'access point
-  -c pour l'adresse MAC de la cible

https://www.aircrack-ng.org/doku.php?id=deauthentication

Maintenant il faut que l'on trouve les adresses MACs que nous voulons. Pour la cible c'est assez simple, nous l'avons récupéré avec la commande ```ifconfig```. C'est également possible de la trouver dans les réglages Wi-Fi (cela depend de l'OS et/ou de la distribution).

![](./images/MAC_c.png)

Afin de trouver le BSSID de l'access point il est possible de le trouver directement dans les réglages Wi-Fi. Cependant si ce n'est pas possible, comme dans le cas d'une distribution PopOS!, on peut utiliser la commande ```nmcli -f SSID,BSSID,ACTIVE dev wifi list | grep HEIG-VD```

![](./images/BSSID.png)

La commande finale ressemble à ça :

``aireplay-ng -00 -a 7C:95:F3:00:79:DF -c 28:11:A8:5A:D7:D2 wlan0mon``

Cependant l'access point était en 5GHz sur un canal 100 et le monitor n'est que sur du 2.4GHz. Nous avons alors trouvé un autre access point sur 2.4 sur le canal 11. Nous avons alors mis le monitor sur le canal 11.

__Question__ : quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interpretation ?

Le code utilisé par aircrack est le 7, il signifie que le client a tenté de transférer des données avant d'être associé à l'acces point.

![](./images/dehaut5.png)

__Question__ : A l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interpretation ?

Nous utilisons ce filtre là afin de n'avoir que les trames de déhautentification :
```(wlan.fc.type == 0) && (wlan.fc.type_subtype == 0x0c)```

Nous avons laissé tourner wireshark pendant un moment et nous avons sniffé plusieurs déhautentification, celle-ci possède le *Reason Code* n°1 - sans raison spécifique.

![](./images/dehaut1.png)

Une autre possède le *Reason Code* n°2 - le client est associé mais n'est pas autorisé.

![](./images/dehaut2.png)
Une autre avec le *Reason Code* inconnu :

![](./images/dehaut3.png)

Une autre avec le *Reason Code* 15 - 4way handhsake timeout

![](./images/dehauth4.png)

https://support.zyxel.eu/hc/fr/articles/360009469759-Quelle-est-la-signification-des-codes-de-motif-de-d%C3%A9sauthentification-802-11-

b) Développer un script en Python/Scapy capable de générer et envoyer des trames de déauthentification. Le script donne le choix entre des Reason codes différents (liste ci-après) et doit pouvoir déduire si le message doit être envoyé à la STA ou à l'AP :

* 1 - Unspecified
* 4 - Disassociated due to inactivity
* 5 - Disassociated because AP is unable to handle all currently associated stations
* 8 - Deauthenticated because sending STA is leaving BSS

**Fonctionnement:**
Installation et utilisation :

* `sudo pip install scapy`
* `python3 1_deauth.py -i <Interface name> -b <AP BSSID> -c <Client MAC address> [-n <Nombre de frames à envoyer>]`

Tips :
Un téléphone android peut être paramêtré en mode partage de connexion 2.4GHz avec adresse MAC fixe du téléphone. Nous avons utilisé l'AP NicOPPO d'un téléphone Android. Pour connaître le BSSID nous avons utilisé la même commande expliquée auparavant :

![](./images/nicOPPO.png)

Lancement du script, lors du lancement il nous demande quel type de Reason Code on veut utiliser, il faut utiliser le numéro :

![](./images/command_deauth.png)

 Nous avons lancé 200 paquets avec le Reason Code 4 ce qui nous a déauthentifier le laptop client, une pop-up demandant d'entrer à nouveau le mot de passe de l'AP est apparu. Nous avons fait une capture des 4-way handshake depuis wireshark et nous pouvons bien le confirmer :

![](./images/wireshark_deauth.png)

__Question__ : quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

Les Reason Coe 1, 4 et 5.

- 1 - Unspecified : ce code pourrait être envoyé par les deux car la raison n'est pas spécifiée. Dans le script nous l'avons mis dans cette catégorie.
- 4 - Disassociated due to inactivity :  ce code est envoyé par l'AP à la STA quand celle-ci est inactive depuis un moment pour libérer un peu de place à l'AP.
- 5 - Disassociated because AP is unable to handle all currently associated stations : ce code montre que l'AP a un soucis et c'est donc elle qui va notifier une STA afin qu'elle se désauthentifie.

__Question__ : quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

Les Reason Code 1 et 8.

- 1 - Unspecified : comme dit auparavant, on ne connaît pas la raison- La trame pourrait être envoyée par les deux côtés.
- 8 - Deauthenticated because sending STA is leaving BSS : ici c'est la STA qui a un soucis et qui doit annoncer à l'AP qu'il se désauthentifie.

__Question__ : Comment essayer de déauthentifier toutes les STA ?

En utilisant l'adresse MAC de broadcast (**FF:FF:FF:FF:FF:FF**) en tant que cible. 

__Question__ : Quelle est la différence entre le code 3 et le code 8 de la liste ?

Dans les deux cas la raison est que la STA sort d'un réseau. Dans le cas 3 la STA sort (ou est sorti) d'un IBSS ou ESS alors que dans le cas 8 il sort d'un BSS. Pour comprendre la différence il faut comprendre ce qu'est un réseau **IBSS** , **ESS** et un **BSS**.

- IBSS (Independant Basic Service set) : quand deux ou plusieurs appareils se connectent directement sans AP (ad hoc).
- BSS (Basic Service Set) : quand des clients se connecte à un réseau via un AP. C'est ce qui est utilisé pour la plupart des réseau wifi. 
- ESS (Extended Service Set) : quand plusieurs STA recoivent le signal d'un seul SSID et ils créent un WLAN entre eux. 

__Question__ : Expliquer l'effet de cette attaque sur la cible

Lorsqu'on lance cette attaque, elle va désauthentifier la cible. Quand nous avons testé cela n'a pas toujours marché et cela dépend également de quel Reason Code on utilise. Donc elle va se désauthentifier et va  refaire un 4-way handshake afin de s'authentifier à nouveau. C'est à ce moment là qu'on va pouvoir récupérer le 4-way handshake afin de récupérer des informations sur les clés que nous pourront alors essayer de déchiffrer à côté. On pourrait également générer un AP spoofé, puis on désauthentifie la cible de l'AP qu'on a spoofé. Lorsque la cible va s'authentifier à nouveau il peut le faire sur notre AP au lieu de la réele.

### 2. Fake channel evil tween attack
a)	Développer un script en Python/Scapy avec les fonctionnalités suivantes :

* Dresser une liste des SSID disponibles à proximité
* Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances
* Permettre à l'utilisateur de choisir le réseau à attaquer
* Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original

__Question__ : Expliquer l'effet de cette attaque sur la cible
Une cible pourrait se connecter  à notre faux AP à la place de l'AP qu'elle avait l'intention d'utiliser. Cela peut permettre de faire des attaques Man-in-the-middle où de voler les credentials de la cible en reproduisant une page d'authentification de l'AP originel qui s'ouvre à la connexion à l'AP.

**Fonctionnement:**

```sudo pip install faker```

`sudo pip install scapy`

```sudo python3 2_fake_channel_evil_tween.py -i <Interface name>```

```sudo python3 2_fake_channel_evil_tween.py -i <Interface name> -t <Time in seconds>```

* Nous allons choisir de spoofer l'AP dont le SSID est **netplus-6e8440**,et on devrait spoofer un AP avec le même SSID, et un autre MAC (généré aléatoirement)

* La frame pour spoofer l'AP est ensuite envoyée en continue

  ![](.README_images/evilchannel.png)

* Pour vérifier que cela fonctionne, on lance en parallèle un autre scan `Scan.py` qui fonctionne de la même façon pour découvrir les APs à proximité.

* Nous voyons bien qu'il y a un deuxième AP dont l'SSID est **netplus-6e8440** avec une adresse MAC différente

  ![](.README_images/evilchannelverif.png)

  Ici on met une adresse MAC random, on pourrait reprendre l'adresse MAC de l'AP qu'on spoof.

### 3. SSID flood attack

Développer un script en Python/Scapy capable d'inonder la salle avec des SSID dont le nom correspond à une liste contenue dans un fichier text fournit par un utilisateur. Si l'utilisateur ne possède pas une liste, il peut spécifier le nombre d'AP à générer. Dans ce cas, les SSID seront générés de manière aléatoire.

**Fonctionnement:**

```sudo pip install faker```

```sudo pip install thread```

```sudo pip install names```

`sudo pip install scapy`

```sudo python3 3_SSID_flooding.py -i <Interface name>```

```sudo python3 3_SSID_flooding.py -i <Interface name> -f <File>``` 

On a lancé le code avec génération de 3 SSID aléatoires.

![](./images/start1.png)

Voici le résultat depuis mon téléphone 

![](./images/wifi_2.png)

Ensuite on a essayé avec un fichier 

![](./images/test3.png)

Voici le résultat depuis mon laptop:

![](./images/ssid_list.png)

Toute cette partie est faite en mode monitor avec channel hopping car on veut envoyer les beacons sur tous les canaux pour essayer d'atteindre le plus de STA possible. 


## Partie 2 - probes

## Introduction

L’une des informations de plus intéressantes et utiles que l’on peut obtenir à partir d’un client sans fils de manière entièrement passive (et en clair) se trouve dans la trame ``Probe Request`` :

![Probe Request et Probe Response](images/probes.png)

Dans ce type de trame, utilisée par les clients pour la recherche active de réseaux, on peut retrouver :

* L’adresse physique (MAC) du client (sauf pour dispositifs iOS 8 ou plus récents et des versions plus récentes d'Android). 
	* Utilisant l’adresse physique, on peut faire une hypothèse sur le constructeur du dispositif sans fils utilisé par la cible.
	* Elle peut aussi être utilisée pour identifier la présence de ce même dispositif à des différents endroits géographiques où l’on fait des captures, même si le client ne se connecte pas à un réseau sans fils.
* Des noms de réseaux (SSID) recherchés par le client.
	* Un Probe Request peut être utilisé pour « tracer » les pas d’un client. Si une trame Probe Request annonce le nom du réseau d’un hôtel en particulier, par exemple, ceci est une bonne indication que le client s’est déjà connecté au dit réseau. 
	* Un Probe Request peut être utilisé pour proposer un réseau « evil twin » à la cible.

Il peut être utile, pour des raisons entièrement légitimes et justifiables, de détecter si certains utilisateurs se trouvent dans les parages. Pensez, par exemple, au cas d'un incendie dans un bâtiment. On pourrait dresser une liste des dispositifs et la contraster avec les personnes qui ont déjà quitté le lieu.

A des fins plus discutables du point de vue éthique, la détection de client s'utilise également pour la recherche de marketing. Aux Etats Unis, par exemple, on "sniff" dans les couloirs de centres commerciaux pour détecter quelles vitrines attirent plus de visiteurs, et quelle marque de téléphone ils utilisent. Ce service, interconnecté en réseau, peut aussi déterminer si un client visite plusieurs centres commerciaux un même jour ou sur un certain intervalle de temps.

### 4. Probe Request Evil Twin Attack

Nous allons nous intéresser dans cet exercice à la création d'un evil twin pour viser une cible que l'on découvre dynamiquement utilisant des probes.

Développer un script en Python/Scapy capable de detecter une STA cherchant un SSID particulier - proposer un evil twin si le SSID est trouvé (i.e. McDonalds, Starbucks, etc.).

Pour la détection du SSID, vous devez utiliser Scapy. Pour proposer un evil twin, vous pouvez très probablement réutiliser du code des exercices précédents ou vous servir d'un outil existant.

**Fonctionnement:**

```sudo pip install faker```

`sudo pip install scapy`

```sudo python3 4_Detect_probeRequest_evil_tween.py -i <Interface name> ```

```sudo python3 4_Detect_probeRequest_evil_tween.py -i <Interface name> -t <Time in seconds>```

Nous commençons par lancer le programme avec un temps de recherche de 30 secondes (par default). Il me demande si je veut lancer un evil tween du SSID trouvé.

![](./images/4.script.png)

Pour vérifier l'evil tween on lui a mis un BSSID de **22:22:22:22:22:22**, et on lance le script de scanning pour voir les SSID alentours :

![](./images/scan4.png)

L'evil tween est bien présent.

__Question__ : comment ça se fait que ces trames puissent être lues par tout le monde ? Ne serait-il pas plus judicieux de les chiffrer ?

Ce sont des requêtes dans le but de trouver une AP, un échange de clés cryptographiques n'a pas encore pu être fait. On ne peut donc pas chiffrer ces trames sinon les AP ne les comprendraient pas.

__Question__ : pourquoi les dispositifs iOS et Android récents ne peuvent-ils plus être tracés avec cette méthode ?

Car les nouvelles versions randomisent leur adresse MAC, on ne peut donc pas récupérer ses informations. Par exemple si on veut identifier la présence de ce même dispositif à des différents endroits géographiques on ne pourra pas car ce n'est jamais la même adresse.


### 5. Détection de clients et réseaux

a) Développer un script en Python/Scapy capable de lister toutes les STA qui cherchent activement un SSID donné

**Fonctionnement:**

```sudo pip install faker```

`sudo pip install scapy`

```sudo python3 5.a_Detection_probeRequest.py -i <Interface name> -ssid <SSID name>```

Nous commençons par lancer le programme avec un temps de recherche de 30 secondes (par default) et le SSID McDo. Et j'essaie de me connecter avec mon téléphone sur le SSID McDo pour simuler une recherche active d'un SSID. Voici le résultat :

![](./images/mcdodetect.png)

La recherche fonctionne correctement.

b) Développer un script en Python/Scapy capable de générer une liste d'AP visibles dans la salle et de STA détectés et déterminer quelle STA est associée à quel AP. Par exemple :

STAs &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; APs

B8:17:C2:EB:8F:8F &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 08:EC:F5:28:1A:EF

9C:F3:87:34:3C:CB &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 00:6B:F1:50:48:3A

00:0E:35:C8:B8:66 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 08:EC:F5:28:1A:EF

**Fonctionnement:**

```sudo python3 5.b_Detection_STA_and_link_AP.py -i wlan0mon```

Résultat après avoir lancé le programme:

![](./images/5.b.1.png)

Il trouve plusieurs STA linké avec un AP, on peut vérifier en regardant wireshark :

![](./images/5.b.2.png)


### 6. Hidden SSID reveal (exercices challenge optionnel - donne droit à un bonus)

Développer un script en Python/Scapy capable de reveler le SSID correspondant à un réseau configuré comme étant "invisible".

**Fonctionnement:**

```sudo python3 6_Detection_hidden_SSID.py -i <Interface name>```

```sudo python3 6_Detection_hidden_SSID.py -i <Interface name> -t <Time in seconds>```

On voit tout d'abord les BSSID qu'on a trouvé n'ayant pas de SSID, il faut maintenant attendre qu'une Probe Request arrive. Nous avons simulé l'AP hidden avec un téléphone Android, et nous avons pu nous y connecté (génération de la Probe Response) ensuite pour trouver le SSID.

![](./images/hiddenSSID.png)

__Question__ : expliquer en quelques mots la solution que vous avez trouvée pour ce problème ?

Nous utilisons les trames Beacons afin de trouver le BSSID d'un AP hidden. Pour savoir s'il est caché il suffit de regarder son SSID qui est vide ou plus exactement ```"\x00"``` . On stock alors les BSSID cachés qu'on trouve et on vérifie également les Probe Response. Le but est de recevoir une Probe Response d'une STA voulant se connecter à notre AP cachée. On compare alors les BSSID cachés trouvés avec celui de la trame et si c'est les mêmes on a trouvé notre SSID correspondant.

## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

- Script de Deauthentication de clients 802.11 __abondamment commenté/documenté__

- Script fake chanel __abondamment commenté/documenté__

- Script SSID flood __abondamment commenté/documenté__

- Script evil twin __abondamment commenté/documenté__

- Scripts détection STA et AP __abondamment commenté/documenté__

- Script SSID reveal __abondamment commenté/documenté__


- Captures d'écran du fonctionnement de chaque script

-	Réponses aux éventuelles questions posées dans la donnée. Vous répondez aux questions dans votre ```README.md``` ou dans un pdf séparé

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 31 mars 2022 à 23h59
