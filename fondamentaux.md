# Registres

| Registres | Rôles                                                                | 64 bits | 32 bits |
| --------- | -------------------------------------------------------------------- | ------- | ------- |
| `RAX`     | accumulateur, valeur de retour                                       | RAX     | EAX     |
| `RBX`     | base, pointeur de données                                            | RBX     | EBX     |
| `RDI`     | 1er argument (Linux)                                                 | RDI     | EDI     |
| `RSI`     | 2ème argument (Linux)                                                | RSI     | ESI     |
| `RBP`     | base pointer (base de la stack frame)                                | RBP     | EBP     |
| `RSP`     | stack pointer (correspond à l'endroit où on est dans la stack)       | RSP     | ESP     |
| `RIP`     | instruction pointer (contient l'adresse de la prochaine instruction) | RIP     | EIP     |

>[!TIP]
>## Convention d'appel
>
>**Linux x86 - cdecl**
>
>	Les arguments sont passés directement sur la stack
>
>---
>**System V AMD64 ABI - Linux**
>
>	Les 6 premiers arguments sont passés via les registres: `RDI`,`RSI`, `RDX`,`RCX`, `R8`, `R9`. À partir du 7ème, ils sont passés sur la stack

---
# Instructions Assembleur

| Instructions           | Descriptions                                                                   |
| ---------------------- | ------------------------------------------------------------------------------ |
| `mov <dest>, <source>` | copie la valeur de la source dans la destination (équivalent de `=` en python) |
| `push <valeur>`        | empile une valeur sur la stack (décrémente RSP puis écrit)                     |
| `pop <registre>`       | dépile une valeur de la stack (lit puis incrémente RSP)                        |
| `call <adresse>`       | empile RIP/EIP puis saute à l'adresse (appel de fonction)                      |
| `ret`                  | dépile une adressse et saute desssus (retour de fonction)                      |

---
# Protections
| Protection | Effet si active | Impact sur l'exploitation |
|-----------|----------------|---------------------------|
| **NX** (Non-Executable stack) | La stack n’est pas exécutable | Impossible d’exécuter du shellcode sur la stack: ROP / ret2libc |
| **PIE** | Le binaire est relocalisé à chaque exécution | Les adresses changent: leak nécessaire pour retrouver la base |
| **Canary** (Stack Protector) | Vérification d’intégrité avant le `ret` | Écrasement du canary = crash: leak ou autre vecteur requis |
| **RELRO (partial / full)** | `full` rend la GOT en lecture seule | Empêche le GOT overwrite via `.got.plt` |
| **ASLR** | Randomisation des adresses mémoire | Plus d’adresses fixes: leak requis (libc / stack / heap) |
| **Fortify / SMEP / SMAP** | Protections avancées (surtout kernel) | Limitent certaines primitives, rares en CTF userspace |

