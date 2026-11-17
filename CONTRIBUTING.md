# Guía de trabajo del equipo (RSA-Sign, Grupo D)

Proyecto 2 de ELC107 Criptografía y Seguridad. Cierre: **26 de noviembre, 00:00**.

- Repositorio: https://github.com/alexandervillarroel0078/rsa-sign
- Tablero de tareas: https://docs.google.com/document/d/1TZuLj--m8dE12zY-x1lIonAYU78lUb42DE0Of-kGgGs/edit?usp=sharing

## Cómo trabajamos

No hay reparto fijo. Cada quien elige la siguiente tarea libre cuyo **Requiere** ya esté en Hecho.

1. Antes de empezar: escribe tu nombre en **Responsable** y pon **En curso**.
2. Al terminar: pon **Hecho**.
3. Así nadie repite trabajo ni espera a otro.

Ya están hechas las partes A (SHA-256), B (aritmética modular) y C (Miller-Rabin y generación de primos).

## Preparación (una sola vez)

1. Acepta la invitación como colaborador que llega al correo.
2. Verifica tu identidad en Git. Debe salir tu nombre y el correo de tu cuenta de GitHub:

```
git config user.name
git config user.email
```

Si no sale, configúrala:

```
git config --global user.name "Su Nombre Completo"
git config --global user.email "correo-de-su-github@gmail.com"
```

3. Clona el repositorio:

```
git clone https://github.com/alexandervillarroel0078/rsa-sign.git
```

## Flujo por cada tarea

```
git checkout main
git pull
git checkout -b feat/nombre-de-la-tarea
# trabajar y probar
python -m unittest discover -s tests -v
git add .
git commit -m "mensaje claro"
git push -u origin feat/nombre-de-la-tarea
```

Luego abre un **Pull Request** hacia `main` en GitHub. Nadie sube directo a `main`.

## Reglas

- Python, sin librerías de caja negra en la lógica criptográfica (nada de `hashlib` ni `cryptography`).
- `hashlib` solo se usa en `tests/` para comparar resultados.
- Aleatoriedad solo con `secrets`.
- Código comentado en español y con tests.
- Cada integrante debe poder explicar su parte en la defensa oral.
