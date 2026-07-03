# TPE - Protocolos de Comunicación

<details>
  <summary>Contenidos</summary>
  <ol>
    <li><a href="#instalación">Instalación</a></li>
    <li><a href="#instrucciones">Instrucciones</a></li>
    <li><a href="#limpieza">Limpieza</a></li>
    <li><a href="#integrantes">Integrantes</a></li>
  </ol>
</details>

## Instalación:

### Dependencias

- **Compilar** el servidor y el cliente: `gcc` (C11) y `make`.

```sh
make        # compila server y client en ./bin
```

- **Correr los tests**: además hace falta el framework de unit testing
  [`check`](https://libcheck.github.io/check/) (se usa también en los tests de la cátedra
  en `src/test/`). En Debian/Ubuntu:

```sh
sudo apt-get install check
make test   # compila y corre la suite de tests
```

Sin `check` instalado, `make server`/`make client` funcionan igual; solo `make test` lo requiere.

### Agregar un test nuevo

Los tests viven en `src/test/` y usan el framework [`check`](https://libcheck.github.io/check/).

1. **Crear el archivo** `src/test/<nombre>_test.c`. Se puede tomar como molde
   `src/test/buffer_test.c` (define los casos con `START_TEST`/`END_TEST`, los agrupa en una
   `Suite` y corre un `SRunner` en el `main`). Para poder probar funciones internas (`static`)
   se incluye directamente el `.c` bajo prueba, no el `.h`:

   ```c
   #include <check.h>
   #include "modulo.c"   // incluye el .c para acceder a lo interno
   ```

2. **Cablearlo en el `Makefile`.** Agregar el ejecutable a la lista `TESTS` y escribir su regla
   junto a las demás. La regla linkea solo las **dependencias** del test (los `.c` que usa y que
   no estén ya incluidos por el `#include`):

   ```make
   TESTS=... \
         $(TEST_FOLDER)/modulo_test

   $(TEST_FOLDER)/modulo_test: src/test/modulo_test.c src/shared/modulo.c src/shared/dep.c
       mkdir -p $(TEST_FOLDER)
       $(COMPILER) $(COMPILER_FLAGS) src/test/modulo_test.c src/shared/dep.c $(CHECK_FLAGS) -o $@
   ```

   > Ojo: si el test hace `#include "modulo.c"`, **no** hay que volver a pasar `modulo.c` a la
   > línea de `gcc` (daría "multiple definition"); sí se listan sus dependencias (p.ej. `buffer.c`).
   > Los `.c` que se incluyen inline igual se listan como prerequisito (después de los `:`) para
   > que un cambio dispare la recompilación.

3. **Correrlo:** `make test` compila y ejecuta toda la suite; corta con error si alguno falla.

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

## Instrucciones:

### Servidor Proxy:


### Cliente de Monitoreo:

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

### Comandos del Cliente de Monitoreo:

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

## Limpieza:

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

## Integrantes:

* Josefina Ravera (65690) - jravera@itba.edu.ar
* Magalí Gonzalez Porzio (64028) - mgonzalezporzio@itba.edu.ar
* Azul Grelle (65221) - agrelle@itba.edu.ar

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>