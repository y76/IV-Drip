# Using Your Python Virtual Environment

## Activate the Virtual Environment

From any terminal:

```bash
source ~/venv/charm/bin/activate
```

You’ll know it’s active when your prompt looks like:

```
(charm) pavel@your-pc:~$
```

---

## Deactivate the Virtual Environment

To exit the virtual environment:

```bash
deactivate
```

Your prompt will return to normal:

```
pavel@your-pc:~$
```

---

That’s it — activate to use Charm, deactivate when you're done.

## Useful links
- https://github.com/JHUISI/charm
- https://github.com/blynn/pbc/tree/master

```
(charm) pavel@pavel:~/apps/IV-Drip$ python IVDrip.py
73640224791758403476681047032923996554157944894
```


## Update your bashrc

```
ivdrip() {
  echo "Setting up IV-Drip environment..."
  cd ~/apps/IV-Drip || return
  source ~/venv/charm/bin/activate
  xdg-open . >/dev/null 2>&1 &
  code .
}
```
