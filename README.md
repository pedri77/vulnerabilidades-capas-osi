# Vulnerabilidades y protecciones por capa OSI

[![capas](https://img.shields.io/badge/capas-7%20%2B%20transversal-ef233c?style=flat-square)](data/capas.yaml)
[![clases](https://img.shields.io/badge/clases-41-8d99ae?style=flat-square)](data/capas.yaml)
[![CWE y ATT&CK](https://img.shields.io/badge/CWE%20y%20ATT%26CK-verificados-2ea043?style=flat-square)](data/verificacion_ids.yaml)
[![ENS y NIS2](https://img.shields.io/badge/ENS%20y%20NIS2-mapeado-1f6feb?style=flat-square)](data/ens_ids.txt)
[![histórico](https://img.shields.io/badge/hist%C3%B3rico-1985%20a%202025-ef233c?style=flat-square)](https://pedri77.github.io/vulnerabilidades-capas-osi/historico/)
[![licencia](https://img.shields.io/badge/licencia-MIT-lightgrey?style=flat-square)](LICENSE)

Catálogo de vulnerabilidades y protecciones on-premise ordenado por capa OSI. Para cada capa recoge los activos típicos (switches, routers, firewalls, balanceadores, WAF, servidores) y las clases de ataque que la afectan. Cada clase lleva:

- debilidades **CWE** y técnicas **MITRE ATT&CK** (Enterprise e ICS), comprobadas contra las páginas oficiales;
- protocolos afectados con los ids de [security-manager-control](https://github.com/pedri77/security-manager-control);
- controles de protección on-premise (DAI, DHCP snooping, 802.1X, BCP38, RPKI, límite de tasa, TLS 1.2 y 1.3, WAF...);
- cómo detectarlo (fuente de registros);
- mapeo a medidas del **ENS** (RD 311/2022, Anexo II) y a las letras del **art. 21.2 de NIS2**;
- búsquedas en NVD, ENISA EUVD, CISA KEV y CVE Details en lugar de CVE concretos.

Incluye además una [matriz histórica](https://pedri77.github.io/vulnerabilidades-capas-osi/historico/) de casos concretos de protocolos desde 1985: área funcional, década, fecha con su naturaleza, causa, condición, control y fuente. Cada caso enlaza con su clase del catálogo.

## Relación con los otros repositorios

| Repositorio | Para qué |
| --- | --- |
| [Modelo OSI interactivo](https://pedri77.github.io/modelo_OSI/) | Aprender las 7 capas, PDU y protocolos. |
| [Protección por capas OSI](https://pedri77.github.io/Basicos_Proteccion_Capas_OSI/) | Curso interactivo: señales, simulador de investigación, quiz. |
| Este repositorio | Catálogo de consulta: clase de ataque, CWE, ATT&CK, control, detección y norma. Matriz histórica: casos con fecha y fuente. |
| [security-manager-control](https://github.com/pedri77/security-manager-control) | Evaluación NIS2/ENS; usa este catálogo en la vertical `VRT-OSI`. |

## Uso con SMC (vertical VRT-OSI)

La vertical `VRT-OSI` de SMC puntúa la madurez de la protección on-prem por capas (capas 1 y 2 con 802.1X y NAC, capa 3 con ACL entre zonas, capas 4 y 5 con cortafuegos con estado y antiDDoS, capas 6 y 7 con TLS 1.2+ y WAF). Este repositorio aporta el detalle para evaluarla:

1. Recorrer cada capa de `docs/index.html` y comprobar si los controles de cada clase están aplicados.
2. Anotar en la evaluación de SMC (`verticales: VRT-OSI: {notas: ...}`) los ids de clase sin cubrir, por ejemplo `L2-ARP-SPOOFING` o `L6-TLS-DEBIL`.
3. Las medidas `ENS-*` y `NIS2-21.2.*` de cada clase usan los mismos ids que los catálogos de SMC, así que el hallazgo se traslada sin conversión.
4. Los ids de `protocolos` son los de `vulnerabilities/protocols.yaml` de SMC; desde allí se llega a las búsquedas por protocolo.

Convención de capa: la capa de una clase es la del ataque o su impacto. La de cada protocolo es la de SMC, que puede no coincidir (SMC pone BGP y DHCP en la capa 7; aquí aparecen en clases de capa 3 y 2).

## Estructura

```text
data/capas.yaml              catálogo: 7 capas + transversal, 41 clases
data/fuentes.yaml            fuentes oficiales y guías CCN-STIC
data/ens_ids.txt             73 ids de medidas ENS (copia de SMC, con nota de origen)
data/smc_protocolos.yaml     28 protocolos de SMC con su capa (copia, con nota de origen)
data/historico.yaml          matriz histórica: entradas OSI-NNN y amenazas de capa física
data/historico_fuentes.yaml  fuentes S01 a S51 de la matriz histórica
data/verificacion_ids.yaml   resultado de la comprobación en línea de CWE, ATT&CK, CVE y URL
tools/validar.py             esquema, formatos de id, ENS, https y lista blanca de enlaces
tools/verificar_ids.py       comprueba ids y URL contra cwe.mitre.org, attack.mitre.org y las fuentes
tools/generar.py             genera docs/index.html, docs/capas.md y docs/historico/
tools/generar_historico.py   genera la matriz histórica (CSS y JS en tools/historico_estaticos/)
tests/                       tests con mutaciones y contrapruebas
docs/index.html              página estática para GitHub Pages (sin CDN)
docs/historico/              matriz histórica, usable sin JavaScript
```

## Uso

Requisitos: Python 3.11+ y PyYAML (pytest opcional).

```bash
python tools/verificar_ids.py --urls   # necesita red; reescribe data/verificacion_ids.yaml
python tools/validar.py                # sin red; --publicar rechaza entradas sin revisión humana
python tools/generar.py                # docs/index.html y docs/capas.md
python -m pytest -q                    # o: python -m unittest discover tests
```

Con `uv` sin instalar nada: `uv run --no-project --with pyyaml --with pytest python -m pytest -q`.

## Fuentes

NIST NVD, ENISA EUVD, CISA KEV, CVE Details, MITRE CWE y ATT&CK, INCIBE-CERT, CCN-CERT y guías CCN-STIC 811, 812 y 816, RD 311/2022 y Directiva (UE) 2022/2555. Detalle y URL en [data/fuentes.yaml](data/fuentes.yaml). CCN-CERT, CVE Details y EUR-Lex bloquean clientes automáticos y se marcan para comprobación manual.

## Límites

- Mapeo orientativo: juicio inicial del autor, sin auditoría externa. No sustituye el análisis de riesgos de cada sistema.
- El catálogo no cita CVE concretos a propósito: las búsquedas devuelven los actuales. Los CVE concretos están en la matriz histórica.
- La matriz histórica no es un censo ni cubre 2026 de forma sistemática. Una entrada puede ser un fallo, una familia o una debilidad de diseño: no equivale a un CVE. No acredita exposición de ninguna organización.
- Algunas medidas ENS de SMC llevan `verificar: true` (pendientes de contrastar con el Anexo II).
- Sin datos de clientes ni secretos.

## Licencia

[MIT](LICENSE). Autor: David Moya.
