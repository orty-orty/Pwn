
> [!TIP]
> **Reminder (send payload)**
> 
> argument:
> 	`./binary $(python -c 'print(payload'))`
> 
> stdin:
> 	`python -c 'print(payload) | ./binary'` 

---
# Ret2libc

> [!TIP]
> Objectif
> Trouver la fonction `system()` de la `libc` pour exécuter `/bin/sh` et obtenir un shell.
## Méthodologie
1. `file binaire`: si `dynamically linked` alors la *libc* est externe et il faut la dl (`ldd ./binaire` pour trouver le nom ou utilisation de [[GDB]] )
2. Trouver l'**offset** pour pouvoir contrôler **eip** avec [[Pwntools]]
3. 

| **ASLR désactivé**                                         | **ASLR activé**                                                                               |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Trouver `system`                                           | Leak de la *libc*                                                                             |
| Trouver `/bin/sh`                                          | Calculer la base de la *libc* : `@leak - offset symbole leak dans la libc`                    |
| Payload = `offset + @system + padding fake ebp + @/bin/sh` | Résoudre les adresse de `system` et `/bin/sh` :<br>`@base_libc + offset de system ou /bin/sh` |
|                                                            | Payload = `offset + @system + padding fake ebp + @/bin/sh`                                    |
