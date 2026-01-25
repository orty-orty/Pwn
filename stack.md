
> [!TIP]
> **Reminder (send payload)**
> 
> argument:
> 	`./binary $(python -c 'print(payload'))`
> 
> stdin:
> 	`python -c 'print(payload) | ./binary'` 

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

---
# Ret2libc

> [!TIP]
> Objectif
> Trouver la fonction `system()` de la `libc` pour exécuter `/bin/sh` et obtenir un shell.
## Méthodologie
1. `file binaire`: si `dynamically linked` alors la *libc* est externe et il faut la dl (`ldd ./binaire` pour trouver le nom ou utilisation de [[GDB]] )
2. Trouver l'**offset** pour pouvoir contrôler **eip** avec [Pwntools](./Pwntools.md)
3. 

| **ASLR désactivé**                                         | **ASLR activé**                                                                               |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Trouver `system`                                           | Leak de la *libc*                                                                             |
| Trouver `/bin/sh`                                          | Calculer la base de la *libc* : `@leak - offset symbole leak dans la libc`                    |
| Payload = `offset + @system + padding fake ebp + @/bin/sh` | Résoudre les adresse de `system` et `/bin/sh` :<br>`@base_libc + offset de system ou /bin/sh` |
|                                                            | Payload = `offset + @system + padding fake ebp + @/bin/sh`                                    |
