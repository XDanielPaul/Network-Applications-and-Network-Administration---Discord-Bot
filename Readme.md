## **Readme súbor pre ISA projekt**
Meno a priezvisko: Daniel Paul 
Login: xpauld00
 
## Popis a použitie
Program pôsobí ako bot na komunikačnej platforme Discord.
Bot sa pripojí na kanal #isabot a bude zachytávať a opakovat’ vsetky správy odoslané do kanálu uživateľmi, ktorí nemajú v mene podreťazec ”bot” vo formáte: ”echo: <username> - <message>”.

Spustenie:
 ./isabot[-h |- -help] [-v |- -verbose] -t < bot_access_token >

Spustenie programu bez argumentov zobrazí nápovedu.
Argumenty:
[-h|- -help] - zobrazí nápovedu. (Nepovinný argument)
[-v|- -verbose] - bude vypisovať botom opakovanu správu na štandartný výstup vo formáte
<channel> - <username>: <message>. (Nepovinný argument)
-t <bot_access_token> - za < bot_access_token > treba vloziť token používaneho bota. (Povinný argument)

Príklad spustenia:
./isabot -t "XXXXXXXXXXXXXXXXXXXXXXX.XXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXX" --verbose

Kompletná dokumentácia programu je popísaná v súbore manual.pdf

## Zoznam odovzdaných súborov
isabot.cpp
Makefile
manual.pdf
readme.md
