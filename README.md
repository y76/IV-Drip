# Using Your Python Virtual Environment

## Activate the Virtual Environment

TODO: complete README

From any terminal:

```bash
source ~/venv/charm/bin/activate
```

---

## Deactivate the Virtual Environment

To exit the virtual environment:

```bash
deactivate
```

Your prompt will return to normal:

---

That’s it — activate to use Charm, deactivate when you're done.

## Useful links
- https://github.com/JHUISI/charm
- https://github.com/blynn/pbc/tree/master



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
