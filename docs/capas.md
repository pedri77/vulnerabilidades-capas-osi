# Vulnerabilidades y protecciones por capa OSI

Generado con `tools/generar.py` desde `data/capas.yaml`. No editar a mano.

## Capa 1 · Física

Medio de transmisión, cableado, radiofrecuencia, puertos físicos y salas donde viven los equipos.

**Activos on-prem típicos:** Armarios y racks de comunicaciones, Cableado estructurado y fibra, Rosetas y puertos de red en puestos, Puntos de acceso Wi-Fi, Salas CPD

### Acceso físico y dispositivos implantados (`L1-ACCESO-FISICO`)

Conexión de equipos no autorizados (implantes de red, mini PC, puntos de acceso) a rosetas libres o armarios abiertos.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-1263](https://cwe.mitre.org/data/definitions/1263.html) |
| ATT&CK | [T1200](https://attack.mitre.org/techniques/T1200/) |
| Protocolos (SMC) | EAP_8021X |
| ENS | ENS-mp.if.1, ENS-mp.eq.4, ENS-op.exp.1 |
| NIS2 | NIS2-21.2.i |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=hardware%20implant&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=hardware%20implant) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=hardware%20implant) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=hardware%20implant) |

Controles:

- Armarios y salas con cierre y control de acceso registrado
- Puertos de switch sin uso deshabilitados (shutdown) y asignados a una VLAN aislada
- 802.1X o NAC en todos los puertos de acceso
- Inventario de equipos conectados contrastado con el inventario de activos

Detección:

- Eventos link up y down del switch (syslog)
- Registro del NAC y del servidor RADIUS
- Control de acceso físico y videovigilancia

### Intercepción del medio (`L1-INTERCEPCION-MEDIO`)

Derivación pasiva (TAP) en cobre o fibra o captura de radiofrecuencia para leer tráfico sin cifrar.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) |
| Protocolos (SMC) | TELNET, FTP, HTTP |
| ENS | ENS-mp.com.2, ENS-mp.if.1 |
| NIS2 | NIS2-21.2.h, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=cleartext%20transmission&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=cleartext%20transmission) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=cleartext%20transmission) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=cleartext%20transmission) |

Controles:

- Canalizaciones protegidas y cableado en zonas controladas
- MACsec (IEEE 802.1AE) en enlaces entre edificios o salas sin control
- Cifrado extremo a extremo (TLS, SSH, IPsec) para que la captura no sirva

Detección:

- Alarmas de pérdida de señal o atenuación en fibra
- Inspección física periódica del cableado

## Capa 2 · Enlace de datos

Tramas, direcciones MAC, switches, VLAN y Wi-Fi; decide quién habla dentro del segmento.

**Activos on-prem típicos:** Switches de acceso y distribución, Controladoras y puntos de acceso Wi-Fi, Servidores RADIUS y NAC, Servidores DHCP

### ARP spoofing (envenenamiento de caché ARP) (`L2-ARP-SPOOFING`)

Respuestas ARP falsas para suplantar la puerta de enlace y ponerse en medio del tráfico.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-290](https://cwe.mitre.org/data/definitions/290.html) |
| ATT&CK | [T1557.002](https://attack.mitre.org/techniques/T1557/002/), [T1040](https://attack.mitre.org/techniques/T1040/) |
| Protocolos (SMC) | ARP |
| ENS | ENS-mp.com.3, ENS-op.exp.2, ENS-op.mon.1 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=ARP%20spoofing&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=ARP%20spoofing) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=ARP%20spoofing) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=ARP%20spoofing) |

Controles:

- Dynamic ARP Inspection (DAI) apoyado en la tabla de DHCP snooping
- Entradas ARP estáticas para pasarelas críticas
- Port security y VLAN pequeñas por función

Detección:

- Registros de DAI en el switch
- Cambios de MAC de la puerta de enlace (arpwatch o NDR)
- IDS de red

### MAC flooding (`L2-MAC-FLOODING`)

Inundación de la tabla CAM del switch para que reenvíe tramas a todos los puertos como un concentrador.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-op.exp.2, ENS-op.mon.3 |
| NIS2 | NIS2-21.2.a |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=MAC%20flooding&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=MAC%20flooding) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=MAC%20flooding) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=MAC%20flooding) |

Controles:

- Port security con número máximo de MAC por puerto y acción shutdown o restrict
- 802.1X en puertos de acceso
- Alertas por llenado de la tabla CAM

Detección:

- Violaciones de port security (syslog o SNMP traps)
- Uso de la tabla CAM en la monitorización del switch

### VLAN hopping (`L2-VLAN-HOPPING`)

Salto de VLAN por negociación automática de troncales (switch spoofing) o doble etiquetado 802.1Q.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) |
| ATT&CK | [T1599](https://attack.mitre.org/techniques/T1599/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-op.exp.2, ENS-op.exp.3, ENS-mp.com.4 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=VLAN%20hopping&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=VLAN%20hopping) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=VLAN%20hopping) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=VLAN%20hopping) |

Controles:

- Deshabilitar la negociación dinámica de troncales en puertos de acceso
- Puertos de acceso fijos (modo access) y troncales con lista explícita de VLAN permitidas
- VLAN nativa sin uso y etiquetada en troncales; no usar la VLAN 1

Detección:

- Cambios de configuración de puertos (syslog y gestor de configuración)
- Tráfico entre VLAN no esperado en NDR

### Manipulación de STP (`L2-STP`)

Envío de BPDU para convertirse en puente raíz, desviar tráfico o provocar recálculos continuos de la topología.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) |
| ATT&CK | [T1557](https://attack.mitre.org/techniques/T1557/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-op.exp.2, ENS-op.mon.3 |
| NIS2 | NIS2-21.2.a |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=spanning%20tree&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=spanning%20tree) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=spanning%20tree) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=spanning%20tree) |

Controles:

- BPDU Guard en puertos de usuario y PortFast solo en puertos de borde
- Root Guard en puertos que nunca deben llevar al puente raíz
- Prioridad de puente raíz fijada en los equipos de núcleo

Detección:

- Cambios de topología y de puente raíz (syslog
- SNMP traps)
- Puertos en err-disabled por BPDU Guard

### DHCP spoofing y agotamiento (`L2-DHCP-SPOOFING`)

Servidor DHCP falso que entrega otra puerta de enlace o DNS, o agotamiento del ámbito con solicitudes masivas.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-346](https://cwe.mitre.org/data/definitions/346.html), [CWE-770](https://cwe.mitre.org/data/definitions/770.html) |
| ATT&CK | [T1557.003](https://attack.mitre.org/techniques/T1557/003/) |
| Protocolos (SMC) | DHCP |
| ENS | ENS-op.exp.2, ENS-mp.com.3 |
| NIS2 | NIS2-21.2.a |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=DHCP%20spoofing&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=DHCP%20spoofing) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=DHCP%20spoofing) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=DHCP%20spoofing) |

Controles:

- DHCP snooping con puertos de confianza solo hacia los servidores legítimos
- Límite de tasa de DHCP por puerto
- Port security para frenar el agotamiento por MAC aleatorias

Detección:

- Registros de DHCP snooping
- Avisos de servidor DHCP no autorizado
- Ocupación del ámbito en el servidor DHCP

### Punto de acceso falso y gemelo malvado (`L2-WIFI-ROGUE`)

Red Wi-Fi que imita la corporativa para capturar credenciales EAP o ponerse en medio.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-295](https://cwe.mitre.org/data/definitions/295.html), [CWE-522](https://cwe.mitre.org/data/definitions/522.html) |
| ATT&CK | [T1557](https://attack.mitre.org/techniques/T1557/), [T1040](https://attack.mitre.org/techniques/T1040/) |
| Protocolos (SMC) | EAP_8021X |
| ENS | ENS-mp.com.2, ENS-op.acc.6, ENS-op.mon.1 |
| NIS2 | NIS2-21.2.h, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=rogue%20access%20point&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=rogue%20access%20point) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=rogue%20access%20point) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=rogue%20access%20point) |

Controles:

- WPA3-Enterprise o WPA2-Enterprise con EAP-TLS
- Validación del certificado del servidor RADIUS en los clientes (perfil gestionado)
- Detección y contención de puntos de acceso no autorizados (WIDS/WIPS)

Detección:

- WIDS/WIPS de la controladora
- Registros del servidor RADIUS (fallos de EAP)

### Cifrado y gestión Wi-Fi débiles (`L2-WIFI-CIFRADO`)

WEP, WPS por PIN, handshakes vulnerables y tramas de gestión sin proteger que permiten descifrar, inyectar o desconectar clientes.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-323](https://cwe.mitre.org/data/definitions/323.html), [CWE-306](https://cwe.mitre.org/data/definitions/306.html) |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/), [T1557](https://attack.mitre.org/techniques/T1557/) |
| Protocolos (SMC) | EAP_8021X |
| ENS | ENS-mp.com.2, ENS-mp.com.3, ENS-op.exp.4 |
| NIS2 | NIS2-21.2.e, NIS2-21.2.h |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=WPA2%20Wi-Fi&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=WPA2%20Wi-Fi) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=WPA2%20Wi-Fi) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=WPA2%20Wi-Fi) |

Controles:

- Retirar WEP y deshabilitar WPS por PIN
- WPA3 o WPA2 con tramas de gestión protegidas (802.11w) donde sea compatible
- Firmware de puntos de acceso y controladores de clientes al día según el aviso de cada CVE

Detección:

- WIDS/WIPS de la controladora (desautenticaciones masivas)
- Inventario de firmware de puntos de acceso y clientes

### Cifrado y autenticación Bluetooth (`L2-BLUETOOTH`)

Negociación de clave débil y suplantación de dispositivos emparejados en Bluetooth BR/EDR, con atacante próximo.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-290](https://cwe.mitre.org/data/definitions/290.html) |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/), [T1557](https://attack.mitre.org/techniques/T1557/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-mp.eq.3, ENS-op.exp.2, ENS-op.exp.4 |
| NIS2 | NIS2-21.2.e, NIS2-21.2.h |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=Bluetooth%20BR%20EDR&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=Bluetooth%20BR%20EDR) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=Bluetooth%20BR%20EDR) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=Bluetooth%20BR%20EDR) |

Controles:

- Firmware y controladores Bluetooth al día según el aviso del fabricante
- Exigir longitud mínima de clave donde el dispositivo lo permita
- Deshabilitar Bluetooth en equipos gestionados que no lo necesiten

Detección:

- Inventario de firmware y controladores Bluetooth
- Sensores Bluetooth propios (un WIDS Wi-Fi no lo ve)

### Suplantación de MAC para saltar el NAC (`L2-NAC-BYPASS`)

Copia de la MAC de un equipo autorizado (impresora, teléfono IP) para entrar por puertos con autenticación solo por MAC.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-290](https://cwe.mitre.org/data/definitions/290.html) |
| ATT&CK | [T1200](https://attack.mitre.org/techniques/T1200/) |
| Protocolos (SMC) | EAP_8021X |
| ENS | ENS-op.acc.1, ENS-mp.eq.4 |
| NIS2 | NIS2-21.2.i |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=MAC%20authentication%20bypass&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=MAC%20authentication%20bypass) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=MAC%20authentication%20bypass) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=MAC%20authentication%20bypass) |

Controles:

- 802.1X con EAP-TLS en lugar de autenticación solo por MAC
- Perfilado de dispositivos en el NAC y VLAN restringida para equipos sin 802.1X
- MACsec donde el equipo lo soporte

Detección:

- NAC (misma MAC en dos puertos
- perfil distinto del esperado)
- Registros RADIUS

## Capa 3 · Red

Direccionamiento IP, enrutamiento, ICMP, fragmentación y túneles entre redes.

**Activos on-prem típicos:** Routers de borde y de núcleo, Firewalls perimetrales e internos, Concentradores VPN, Switches de capa 3

### IP spoofing (`L3-IP-SPOOFING`)

Paquetes con dirección de origen falsa para evadir filtros o reflejar tráfico contra un tercero.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-290](https://cwe.mitre.org/data/definitions/290.html) |
| ATT&CK | [T1498.002](https://attack.mitre.org/techniques/T1498/002/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-mp.com.1, ENS-op.exp.2 |
| NIS2 | NIS2-21.2.a |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=IP%20spoofing&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=IP%20spoofing) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=IP%20spoofing) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=IP%20spoofing) |

Controles:

- Filtrado de entrada y salida según BCP38 (RFC 2827) en el borde
- uRPF en modo estricto en interfaces hacia usuarios
- ACL antispoofing (rangos privados y propios entrando desde fuera)

Detección:

- Contadores de descarte por uRPF y ACL
- NetFlow o IPFIX en el borde

### Ataques al enrutamiento (`L3-ENRUTAMIENTO`)

Secuestro o fuga de prefijos BGP e inyección de rutas en protocolos internos (OSPF, EIGRP) sin autenticar.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-306](https://cwe.mitre.org/data/definitions/306.html) |
| ATT&CK | [T1557](https://attack.mitre.org/techniques/T1557/) |
| Protocolos (SMC) | BGP |
| ENS | ENS-mp.com.1, ENS-mp.com.3, ENS-op.exp.2 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=BGP&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=BGP) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=BGP) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=BGP) |

Controles:

- RPKI con validación de origen (ROV) y filtrado de prefijos por vecino
- Límite de prefijos y autenticación de sesiones (TCP-AO o MD5) en BGP
- Autenticación en OSPF y EIGRP e interfaces pasivas donde no hay vecinos

Detección:

- Cambios de vecindad y de tabla de rutas (syslog)
- Monitorización externa de anuncios de prefijos propios

### Abuso de la fragmentación (`L3-FRAGMENTACION`)

Fragmentos solapados o diminutos para evadir el IDS o agotar el reensamblado del destino.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-130](https://cwe.mitre.org/data/definitions/130.html), [CWE-770](https://cwe.mitre.org/data/definitions/770.html) |
| ATT&CK | [T1499.001](https://attack.mitre.org/techniques/T1499/001/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-op.mon.1, ENS-op.exp.4 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=IP%20fragmentation&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=IP%20fragmentation) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=IP%20fragmentation) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=IP%20fragmentation) |

Controles:

- Reensamblado y normalización de fragmentos en el firewall o IPS antes de inspeccionar
- Descarte de fragmentos solapados y de fragmentos iniciales demasiado pequeños
- Firmware al día en equipos que reensamblan

Detección:

- Alertas de anomalía de fragmentación en el IDS/IPS
- Contadores de fragmentos descartados en el firewall

### Abuso de ICMP (`L3-ICMP`)

Reconocimiento, túneles encubiertos sobre ICMP, redirecciones e inundación.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) |
| ATT&CK | [T1018](https://attack.mitre.org/techniques/T1018/), [T1095](https://attack.mitre.org/techniques/T1095/), [T1498](https://attack.mitre.org/techniques/T1498/) |
| Protocolos (SMC) | ICMP |
| ENS | ENS-mp.com.1, ENS-op.mon.1 |
| NIS2 | NIS2-21.2.a |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=ICMP&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=ICMP) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=ICMP) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=ICMP) |

Controles:

- Permitir solo los tipos ICMP necesarios (por ejemplo, los de PMTUD) en el perímetro
- Deshabilitar ICMP redirect en routers y servidores
- Límite de tasa de ICMP

Detección:

- NetFlow (volumen y tamaño de carga ICMP)
- IDS de red

### Anuncios de router IPv6 falsos (`L3-IPV6-RA`)

Router Advertisement o DHCPv6 falsos en redes donde IPv6 está activo sin gestionar, para ponerse en medio.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) |
| ATT&CK | [T1557](https://attack.mitre.org/techniques/T1557/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-op.exp.2, ENS-mp.com.3 |
| NIS2 | NIS2-21.2.a |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=IPv6%20router%20advertisement&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=IPv6%20router%20advertisement) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=IPv6%20router%20advertisement) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=IPv6%20router%20advertisement) |

Controles:

- RA Guard y DHCPv6 Guard en switches de acceso
- Gestionar IPv6 de forma explícita (o deshabilitarlo en el sistema si no se usa)
- Inspección de Neighbor Discovery donde el switch la soporte

Detección:

- Registros de RA Guard
- NDR (routers IPv6 no esperados)

### VPN y túneles débiles o sin parchear (`L3-VPN`)

IPsec con claves precompartidas débiles o algoritmos obsoletos y concentradores VPN expuestos sin parches.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-521](https://cwe.mitre.org/data/definitions/521.html) |
| ATT&CK | [T1133](https://attack.mitre.org/techniques/T1133/), [T1190](https://attack.mitre.org/techniques/T1190/) |
| Protocolos (SMC) | IPSEC_IKE |
| ENS | ENS-op.acc.5, ENS-op.exp.4, ENS-mp.com.2 |
| NIS2 | NIS2-21.2.e, NIS2-21.2.h, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=IKE&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=IKE) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=IKE) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=IKE) |

Controles:

- IKEv2 con certificados y algoritmos modernos
- Parcheo prioritario de VPN perimetrales (vigilar CISA KEV)
- MFA en el acceso remoto

Detección:

- Registros del concentrador VPN (autenticaciones y errores)
- Alertas de inicio de sesión anómalo en el SIEM

## Capa 4 · Transporte

Puertos, TCP y UDP, establecimiento de conexión, estado y presión sobre los servicios.

**Activos on-prem típicos:** Firewalls con estado, Balanceadores de carga, Protección antiDDoS, Servidores con servicios publicados

### SYN flood (`L4-SYN-FLOOD`)

Conexiones TCP a medio abrir que agotan la tabla de estado del servidor, el firewall o el balanceador.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) |
| ATT&CK | [T1499.001](https://attack.mitre.org/techniques/T1499/001/), [T1498.001](https://attack.mitre.org/techniques/T1498/001/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-mp.s.4, ENS-op.pl.4 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.c |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=SYN%20flood&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=SYN%20flood) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=SYN%20flood) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=SYN%20flood) |

Controles:

- SYN cookies en servidores y balanceadores
- Límites de conexiones embrionarias y de tasa por origen en el firewall
- Protección antiDDoS aguas arriba (operador o servicio) para volumen

Detección:

- Contadores de conexiones medio abiertas del firewall o balanceador
- NetFlow
- Monitorización de disponibilidad

### Denegación de servicio en la pila TCP (`L4-DOS-PILA`)

Fallos del núcleo al tratar SACK, MSS u otras opciones de TCP con los que una conexión remota provoca caída o consumo excesivo de recursos.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-190](https://cwe.mitre.org/data/definitions/190.html), [CWE-770](https://cwe.mitre.org/data/definitions/770.html) |
| ATT&CK | [T1499.004](https://attack.mitre.org/techniques/T1499/004/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-op.exp.4, ENS-mp.s.4, ENS-op.pl.4 |
| NIS2 | NIS2-21.2.c, NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=TCP%20stack%20denial%20of%20service&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=TCP%20stack%20denial%20of%20service) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=TCP%20stack%20denial%20of%20service) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=TCP%20stack%20denial%20of%20service) |

Controles:

- Núcleo corregido en una rama mantenida o con backport confirmado por el proveedor
- Inventario de versiones de núcleo y de equipos con pila propia
- Mitigaciones temporales (filtrar MSS muy bajo, desactivar SACK) solo tras evaluar su impacto

Detección:

- Registros del núcleo y eventos de caída
- Monitorización de CPU y memoria
- Contadores TCP del sistema

### Reflexión y amplificación UDP (`L4-AMPLIFICACION`)

Servicios UDP propios (DNS, NTP, SNMP) usados como reflectores contra terceros, o la organización como víctima.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-406](https://cwe.mitre.org/data/definitions/406.html) |
| ATT&CK | [T1498.002](https://attack.mitre.org/techniques/T1498/002/) |
| Protocolos (SMC) | DNS, NTP, SNMP |
| ENS | ENS-mp.s.4, ENS-op.exp.2 |
| NIS2 | NIS2-21.2.a |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=amplification&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=amplification) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=amplification) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=amplification) |

Controles:

- Sin resolutores DNS abiertos ni monlist en NTP; SNMP no expuesto a Internet
- Filtrado BCP38 para no originar tráfico falsificado
- Límite de tasa de respuestas (RRL en DNS)

Detección:

- NetFlow (asimetría de tráfico UDP de salida)
- Registros del servidor DNS y NTP

### Secuestro e inyección en sesiones TCP (`L4-SECUESTRO-TCP`)

Inyección de segmentos o RST en conexiones sin cifrar cuando el atacante ve o predice los números de secuencia.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| ATT&CK | [T1557](https://attack.mitre.org/techniques/T1557/) |
| Protocolos (SMC) | TELNET, FTP, BGP |
| ENS | ENS-mp.com.3, ENS-mp.com.2 |
| NIS2 | NIS2-21.2.h, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=TCP%20session%20hijacking&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=TCP%20session%20hijacking) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=TCP%20session%20hijacking) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=TCP%20session%20hijacking) |

Controles:

- Cifrado e integridad en el canal (TLS, SSH, IPsec)
- TCP-AO o MD5 en sesiones BGP
- Firewall con estado que valide números de secuencia

Detección:

- IDS de red (RST anómalos
- desincronización)
- Registros de sesiones caídas en servicios críticos

### Servicios expuestos y escaneo de puertos (`L4-EXPOSICION-PUERTOS`)

Servicios escuchando en todas las interfaces o publicados sin necesidad, descubiertos por escaneo.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html) |
| ATT&CK | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Protocolos (SMC) | SMB, RDP, SSH, TELNET, FTP, SNMP |
| ENS | ENS-mp.com.1, ENS-op.exp.2, ENS-op.mon.1 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.f |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=port%20scan&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=port%20scan) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=port%20scan) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=port%20scan) |

Controles:

- Política de firewall de denegación por defecto y revisión periódica de reglas
- Servicios ligados solo a la interfaz necesaria
- Escaneo propio periódico del perímetro y entre zonas

Detección:

- Registros de denegación del firewall
- NDR o IDS (patrones de escaneo)

## Capa 5 · Sesión

Estado conversacional, autenticación de sesión, tokens, cookies, reanudación y continuidad.

**Activos on-prem típicos:** Proxies inversos y balanceadores con persistencia, Controladores de dominio, Servidores de aplicaciones, Pasarelas RDP

### Robo y fijación de sesión (`L5-SECUESTRO-SESION`)

Robo de cookies o tokens de sesión, fijación de sesión y sesiones que no caducan.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-384](https://cwe.mitre.org/data/definitions/384.html), [CWE-1463](https://cwe.mitre.org/data/definitions/1463.html), [CWE-1464](https://cwe.mitre.org/data/definitions/1464.html) |
| ATT&CK | [T1539](https://attack.mitre.org/techniques/T1539/), [T1550.004](https://attack.mitre.org/techniques/T1550/004/), [T1563](https://attack.mitre.org/techniques/T1563/) |
| Protocolos (SMC) | HTTP, RDP |
| ENS | ENS-op.acc.6, ENS-mp.s.2 |
| NIS2 | NIS2-21.2.i, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=session%20fixation&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=session%20fixation) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=session%20fixation) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=session%20fixation) |

Controles:

- Cookies con Secure, HttpOnly y SameSite; identificador nuevo tras autenticar
- Caducidad por inactividad y absoluta; revocación en el servidor
- Desconexión de sesiones RDP inactivas en las pasarelas

Detección:

- Registros de la aplicación y del proxy inverso (misma sesión desde orígenes distintos)
- Registros de sesiones RDP

### Relé y repetición de autenticación (`L5-RELE-AUTENTICACION`)

Captura y reenvío de autenticaciones NTLM o Kerberos (envenenamiento LLMNR y NBT-NS, relé SMB y LDAP).

| Campo | Valor |
| --- | --- |
| CWE | [CWE-294](https://cwe.mitre.org/data/definitions/294.html), [CWE-522](https://cwe.mitre.org/data/definitions/522.html) |
| ATT&CK | [T1557.001](https://attack.mitre.org/techniques/T1557/001/), [T1550.002](https://attack.mitre.org/techniques/T1550/002/), [T1558](https://attack.mitre.org/techniques/T1558/) |
| Protocolos (SMC) | NTLM, SMB, LDAP, KERBEROS |
| ENS | ENS-op.acc.6, ENS-mp.com.3, ENS-op.exp.2 |
| NIS2 | NIS2-21.2.i, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=NTLM%20relay&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=NTLM%20relay) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=NTLM%20relay) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=NTLM%20relay) |

Controles:

- Firma SMB obligatoria y firma y channel binding en LDAP
- Deshabilitar LLMNR y NBT-NS; restringir y auditar NTLM
- Protección extendida (EPA) en servicios web con autenticación integrada

Detección:

- Eventos de autenticación de los controladores de dominio
- IDS de red (respuestas LLMNR y NBT-NS no esperadas)

## Capa 6 · Presentación

Cifrado, certificados, codificación y formato de los datos que viajan.

**Activos on-prem típicos:** Terminadores TLS (balanceadores y proxies inversos), PKI interna y HSM, Servidores web y de correo, Servidores LDAP

### TLS débil (`L6-TLS-DEBIL`)

Versiones obsoletas (SSL 3.0, TLS 1.0 y 1.1) y suites sin confidencialidad directa o con cifrados rotos.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-326](https://cwe.mitre.org/data/definitions/326.html) |
| ATT&CK | [T1557](https://attack.mitre.org/techniques/T1557/), [T1040](https://attack.mitre.org/techniques/T1040/) |
| Protocolos (SMC) | TLS, HTTP, SMTP, IMAP_POP3, LDAP |
| ENS | ENS-mp.com.2, ENS-mp.com.3, ENS-op.exp.2 |
| NIS2 | NIS2-21.2.h |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=TLS&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=TLS) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=TLS) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=TLS) |

Controles:

- Solo TLS 1.2 y 1.3 con suites AEAD y confidencialidad directa
- Configuración de referencia común para balanceadores, servidores y equipos de red
- Prueba periódica de la configuración TLS de los servicios publicados

Detección:

- Inventario de versiones TLS negociadas (registros del balanceador o NDR)
- Escaneo periódico de configuración

### Degradación y eliminación del cifrado (`L6-DOWNGRADE`)

Forzar una versión o algoritmo más débil, o quitar el cifrado en el arranque (STARTTLS stripping, SSL stripping).

| Campo | Valor |
| --- | --- |
| CWE | [CWE-757](https://cwe.mitre.org/data/definitions/757.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| ATT&CK | [T1557](https://attack.mitre.org/techniques/T1557/) |
| Protocolos (SMC) | TLS, HTTP, SMTP, IMAP_POP3, LDAP |
| ENS | ENS-mp.com.2, ENS-mp.com.3 |
| NIS2 | NIS2-21.2.h, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=downgrade&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=downgrade) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=downgrade) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=downgrade) |

Controles:

- HSTS en servicios web y redirección única a HTTPS
- TLS obligatorio (no oportunista) entre servidores de correo conocidos y LDAPS en lugar de LDAP con STARTTLS opcional
- Deshabilitar versiones antiguas en ambos extremos

Detección:

- Registros del servidor de correo (sesiones sin TLS)
- Registros del balanceador (versión negociada)

### Validación deficiente de certificados (`L6-CERTIFICADOS`)

Clientes o aplicaciones que aceptan certificados caducados, autofirmados o con otro nombre.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-295](https://cwe.mitre.org/data/definitions/295.html), [CWE-297](https://cwe.mitre.org/data/definitions/297.html) |
| ATT&CK | [T1557](https://attack.mitre.org/techniques/T1557/) |
| Protocolos (SMC) | TLS, EAP_8021X, OPCUA |
| ENS | ENS-mp.com.3, ENS-op.exp.10 |
| NIS2 | NIS2-21.2.h |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=certificate%20validation&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=certificate%20validation) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=certificate%20validation) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=certificate%20validation) |

Controles:

- Validación estricta de cadena, nombre y revocación en clientes y aplicaciones
- PKI interna con inventario y ciclo de vida de certificados
- Alertas de caducidad

Detección:

- Inventario de certificados (caducidad
- emisor)
- Errores de validación en registros de clientes y aplicaciones

### Claves criptográficas expuestas o embebidas (`L6-CLAVES`)

Claves privadas en ficheros accesibles, claves embebidas en firmware o aplicaciones y claves compartidas entre equipos.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-321](https://cwe.mitre.org/data/definitions/321.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| ATT&CK | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) |
| Protocolos (SMC) | TLS, SSH |
| ENS | ENS-op.exp.10, ENS-mp.si.2 |
| NIS2 | NIS2-21.2.h |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=hard-coded%20key&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=hard-coded%20key) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=hard-coded%20key) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=hard-coded%20key) |

Controles:

- Claves en HSM o almacén protegido, con permisos mínimos
- Rotación de claves y certificados y una clave por equipo
- Sustituir claves por defecto de fábrica en equipos de red

Detección:

- Auditoría de acceso a ficheros de claves
- Búsqueda periódica de claves en repositorios y comparticiones

## Capa 7 · Aplicación

Protocolos y lógica de usuario (HTTP, DNS, correo, directorio, protocolos industriales), entrada y salida de datos.

**Activos on-prem típicos:** WAF y proxies inversos, Servidores web y de aplicaciones, Servidores DNS, Servidores de correo, Directorio activo, Pasarelas y servidores OT

### Inyección (`L7-INYECCION`)

Datos de entrada que se ejecutan como consulta o comando (SQL, sistema operativo, LDAP).

| Campo | Valor |
| --- | --- |
| CWE | [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-90](https://cwe.mitre.org/data/definitions/90.html) |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Protocolos (SMC) | HTTP, LDAP |
| ENS | ENS-mp.s.2, ENS-mp.sw.1, ENS-mp.sw.2 |
| NIS2 | NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=SQL%20injection&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=SQL%20injection) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=SQL%20injection) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=SQL%20injection) |

Controles:

- Consultas parametrizadas y validación de entrada en el código
- WAF delante de las aplicaciones publicadas
- Cuentas de servicio con privilegios mínimos en base de datos y sistema

Detección:

- Registros del WAF
- Errores de base de datos en registros de la aplicación

### Cross-site scripting (`L7-XSS`)

Código de script inyectado que se ejecuta en el navegador de otro usuario de la aplicación.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| ATT&CK | [T1189](https://attack.mitre.org/techniques/T1189/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/) |
| Protocolos (SMC) | HTTP |
| ENS | ENS-mp.s.2, ENS-mp.sw.1 |
| NIS2 | NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=cross-site%20scripting&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=cross-site%20scripting) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=cross-site%20scripting) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=cross-site%20scripting) |

Controles:

- Codificación de salida según contexto
- Content Security Policy
- WAF y pruebas de seguridad antes de la puesta en servicio

Detección:

- Registros del WAF
- Informes de violación de CSP

### Server-side request forgery (`L7-SSRF`)

La aplicación hace peticiones a destinos internos elegidos por el atacante.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Protocolos (SMC) | HTTP |
| ENS | ENS-mp.s.2, ENS-mp.com.4 |
| NIS2 | NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=SSRF&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=SSRF) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=SSRF) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=SSRF) |

Controles:

- Lista de destinos permitidos en la aplicación
- Salida de los servidores de aplicación filtrada por firewall (sin acceso libre a la red interna)
- WAF con reglas para SSRF

Detección:

- Registros del firewall (conexiones salientes de servidores web a zonas internas)
- Registros del WAF

### Deserialización insegura (`L7-DESERIALIZACION`)

Objetos serializados no confiables que la aplicación reconstruye y que llevan a ejecución de código.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Protocolos (SMC) | HTTP |
| ENS | ENS-mp.sw.1, ENS-op.exp.4 |
| NIS2 | NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=deserialization&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=deserialization) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=deserialization) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=deserialization) |

Controles:

- No deserializar datos no confiables; usar formatos de datos simples con esquema
- Listas de clases permitidas en la deserialización
- Parcheo de librerías y servidores de aplicaciones

Detección:

- Registros del WAF
- EDR en servidores (procesos hijo inesperados del servidor de aplicaciones)

### HTTP request smuggling (`L7-SMUGGLING`)

Proxy y servidor interpretan de forma distinta los límites de una petición HTTP.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-444](https://cwe.mitre.org/data/definitions/444.html) |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Protocolos (SMC) | HTTP |
| ENS | ENS-mp.s.2, ENS-op.exp.4 |
| NIS2 | NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=request%20smuggling&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=request%20smuggling) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=request%20smuggling) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=request%20smuggling) |

Controles:

- Rechazar peticiones con cabeceras de longitud ambiguas en el proxy inverso
- Misma versión de HTTP de extremo a extremo y normalización en el proxy
- Parcheo de proxies y servidores web

Detección:

- Registros del proxy inverso y del WAF
- Discrepancias entre registros del proxy y del servidor

### Credenciales débiles y fuerza bruta (`L7-CREDENCIALES`)

Contraseñas débiles, por defecto o reutilizadas en servicios de acceso remoto y aplicaciones.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-307](https://cwe.mitre.org/data/definitions/307.html), [CWE-521](https://cwe.mitre.org/data/definitions/521.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1133](https://attack.mitre.org/techniques/T1133/) |
| Protocolos (SMC) | RDP, SSH, TELNET, FTP, IMAP_POP3, SIP |
| ENS | ENS-op.acc.5, ENS-op.acc.6 |
| NIS2 | NIS2-21.2.i, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=brute%20force&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=brute%20force) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=brute%20force) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=brute%20force) |

Controles:

- MFA en acceso remoto y cuentas privilegiadas
- Bloqueo o retardo tras intentos fallidos
- No publicar RDP ni SSH a Internet; acceso por VPN o ZTNA

Detección:

- Eventos de autenticación fallida (SIEM)
- Registros de VPN y pasarelas

### Protocolos en texto claro (`L7-TEXTO-CLARO`)

Telnet, FTP, SNMP v1 y v2c, HTTP o LDAP sin cifrar que exponen credenciales y datos.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) |
| Protocolos (SMC) | TELNET, FTP, SNMP, HTTP, LDAP, IMAP_POP3 |
| ENS | ENS-mp.com.2, ENS-op.exp.2 |
| NIS2 | NIS2-21.2.h, NIS2-21.2.j |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=cleartext&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=cleartext) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=cleartext) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=cleartext) |

Controles:

- Sustituir por SSH, SFTP, SNMPv3 con authPriv, HTTPS y LDAPS
- Deshabilitar los servicios en texto claro en equipos de red y servidores

Detección:

- NDR (inventario de protocolos en texto claro)
- Escaneo de servicios

### Abuso de DNS (`L7-DNS`)

Envenenamiento de caché, túneles DNS para exfiltración o mando y control y resolutores abiertos.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-400](https://cwe.mitre.org/data/definitions/400.html) |
| ATT&CK | [T1071.004](https://attack.mitre.org/techniques/T1071/004/), [T1048](https://attack.mitre.org/techniques/T1048/) |
| Protocolos (SMC) | DNS |
| ENS | ENS-op.mon.1, ENS-mp.com.1 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.b |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=DNS&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=DNS) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=DNS) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=DNS) |

Controles:

- Resolutores internos únicos con salida DNS directa bloqueada en el firewall
- DNSSEC en la validación y aleatorización de puertos de origen
- Registro y filtrado de consultas DNS

Detección:

- Registros de consultas DNS (longitud y entropía
- volumen por cliente)
- NDR

### Protocolos industriales sin autenticación (`L7-OT-SIN-AUTENTICACION`)

Modbus, S7, DNP3 o BACnet aceptan órdenes de cualquiera que alcance el puerto.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| ATT&CK | [T1692.001](https://attack.mitre.org/techniques/T1692/001/), [T0846](https://attack.mitre.org/techniques/T0846/), [T0842](https://attack.mitre.org/techniques/T0842/) |
| Protocolos (SMC) | MODBUS, S7COMM, DNP3, BACNET, OPCUA |
| ENS | ENS-mp.com.4, ENS-mp.com.1, ENS-op.mon.1 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=Modbus&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=Modbus) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=Modbus) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=Modbus) |

Controles:

- Zonas y conductos (IEC 62443) con firewall industrial entre TI y OT
- Inspección profunda de protocolos industriales y listas de órdenes permitidas
- Ningún protocolo industrial publicado a Internet

Detección:

- Monitorización pasiva de red OT
- Registros del firewall industrial

### Explotación de servicios publicados sin parchear (`L7-SERVICIOS-PUBLICADOS`)

Vulnerabilidades conocidas en servicios accesibles desde fuera (web, correo, VPN, gestión remota).

| Campo | Valor |
| --- | --- |
| CWE | [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/), [T1133](https://attack.mitre.org/techniques/T1133/) |
| Protocolos (SMC) | HTTP, SMTP, IPSEC_IKE, SMB |
| ENS | ENS-op.exp.4, ENS-op.exp.1, ENS-mp.s.2 |
| NIS2 | NIS2-21.2.e |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=remote%20code%20execution&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=remote%20code%20execution) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=remote%20code%20execution) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=remote%20code%20execution) |

Controles:

- Inventario de servicios publicados con versión y responsable
- Parcheo priorizado por explotación activa (CISA KEV y EUVD)
- Parcheo virtual en WAF o IPS mientras no hay parche

Detección:

- Escaneo de vulnerabilidades autenticado
- Registros del WAF y del IPS

### Denegación de servicio de aplicación (`L7-DOS-APLICACION`)

Peticiones costosas, conexiones lentas o inundación HTTP que agotan la aplicación.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) |
| ATT&CK | [T1499.002](https://attack.mitre.org/techniques/T1499/002/), [T1499.003](https://attack.mitre.org/techniques/T1499/003/) |
| Protocolos (SMC) | HTTP, SIP |
| ENS | ENS-mp.s.4, ENS-op.pl.4, ENS-op.cont.2 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.c |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=denial%20of%20service&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=denial%20of%20service) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=denial%20of%20service) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=denial%20of%20service) |

Controles:

- Límite de tasa por cliente y por ruta en el proxy inverso o WAF
- Tiempos máximos de cabecera y cuerpo en servidores y proxies
- Capacidad dimensionada y plan de continuidad del servicio

Detección:

- Métricas del proxy inverso (latencia
- conexiones abiertas)
- Registros del WAF

## Transversal

Debilidades que cruzan varias capas: segmentación, plano de gestión, registro y ciclo de vida de los equipos.

**Activos on-prem típicos:** Todos los equipos de red y seguridad, Red de gestión, SIEM y recolectores de registros, Servidores de gestión

### Red plana y movimiento lateral (`TX-SEGMENTACION`)

Falta de separación entre zonas que permite saltar de un equipo comprometido al resto.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-653](https://cwe.mitre.org/data/definitions/653.html) |
| ATT&CK | [T1021](https://attack.mitre.org/techniques/T1021/), [T1210](https://attack.mitre.org/techniques/T1210/), [T1570](https://attack.mitre.org/techniques/T1570/) |
| Protocolos (SMC) | SMB, RDP, SSH |
| ENS | ENS-mp.com.4, ENS-op.pl.2, ENS-mp.com.1 |
| NIS2 | NIS2-21.2.a |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=lateral%20movement&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=lateral%20movement) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=lateral%20movement) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=lateral%20movement) |

Controles:

- Zonas por función y criticidad con firewall interno y ACL este-oeste
- Microsegmentación en servidores críticos
- Pruebas de segmentación periódicas

Detección:

- Registros del firewall interno
- NDR (conexiones entre zonas no esperadas)

### Plano de gestión expuesto (`TX-PLANO-GESTION`)

Interfaces de administración, SNMP con comunidades por defecto y cuentas de fábrica accesibles desde la red de usuarios.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| ATT&CK | [T1602.001](https://attack.mitre.org/techniques/T1602/001/), [T1602.002](https://attack.mitre.org/techniques/T1602/002/), [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |
| Protocolos (SMC) | SNMP, SSH, TELNET, HTTP |
| ENS | ENS-op.acc.6, ENS-op.exp.2, ENS-mp.com.4 |
| NIS2 | NIS2-21.2.i, NIS2-21.2.g |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=default%20credentials&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=default%20credentials) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=default%20credentials) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=default%20credentials) |

Controles:

- Red de gestión separada (fuera de banda) y ACL en las interfaces de gestión
- SNMPv3 con authPriv y cambio de credenciales por defecto
- Acceso administrativo con MFA desde puestos dedicados

Detección:

- Registros de acceso administrativo (TACACS+ o RADIUS)
- Registros del firewall hacia la red de gestión

### Firmware sin soporte o modificado (`TX-FIRMWARE`)

Equipos de red fuera de soporte, sin parches o con la imagen del sistema alterada.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html) |
| ATT&CK | [T1601.001](https://attack.mitre.org/techniques/T1601/001/), [T1190](https://attack.mitre.org/techniques/T1190/) |
| Protocolos (SMC) | (general) |
| ENS | ENS-op.exp.1, ENS-op.exp.4, ENS-op.pl.3 |
| NIS2 | NIS2-21.2.e, NIS2-21.2.d |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=firmware&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=firmware) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=firmware) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=firmware) |

Controles:

- Inventario de equipos de red con versión y fecha de fin de soporte
- Parcheo periódico y verificación de la integridad de la imagen (firma o hash)
- Plan de sustitución de equipos sin soporte

Detección:

- Inventario y gestor de configuración (versiones)
- Verificación de hash de imagen

### Túneles y evasión de controles de salida (`TX-TUNELES`)

Tráfico encapsulado en protocolos permitidos (DNS, HTTPS, SSH) para saltar el firewall o el proxy.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| ATT&CK | [T1572](https://attack.mitre.org/techniques/T1572/), [T1090](https://attack.mitre.org/techniques/T1090/) |
| Protocolos (SMC) | DNS, SSH, HTTP |
| ENS | ENS-mp.com.1, ENS-op.mon.1, ENS-mp.s.3 |
| NIS2 | NIS2-21.2.a, NIS2-21.2.b |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=tunneling&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=tunneling) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=tunneling) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=tunneling) |

Controles:

- Salida a Internet solo por proxy y resolutores autorizados
- Inspección TLS donde la política lo permita y bloqueo de túneles no autorizados
- Listas de destinos permitidos para servidores

Detección:

- Registros del proxy y del firewall de salida
- NDR (sesiones largas y volumen anómalo)

### Registro y monitorización insuficientes (`TX-REGISTRO`)

Equipos que no envían registros, relojes desincronizados o retención corta que impiden detectar y reconstruir un ataque.

| Campo | Valor |
| --- | --- |
| CWE | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) |
| ATT&CK | [T1070](https://attack.mitre.org/techniques/T1070/) |
| Protocolos (SMC) | NTP |
| ENS | ENS-op.exp.8, ENS-op.mon.3, ENS-op.exp.7 |
| NIS2 | NIS2-21.2.b, NIS2-21.2.f |
| Buscar CVE | [NVD](https://nvd.nist.gov/vuln/search?keyword=logging&resultType=records) · [EUVD](https://euvd.enisa.europa.eu/search?text=logging) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=logging) · [CVE Details](https://www.cvedetails.com/google-search-results.php?q=logging) |

Controles:

- Registros centralizados de todos los equipos de red y seguridad en el SIEM
- NTP interno común con autenticación
- Retención según la política y alertas por fuentes que dejan de enviar

Detección:

- Cobertura de fuentes del SIEM
- Alertas de silencio de fuentes

## Fuentes

- [NVD](https://nvd.nist.gov/) (NIST (EE. UU.))
- [EUVD](https://euvd.enisa.europa.eu/) (ENISA (UE))
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CISA (EE. UU.))
- [CVE Details](https://www.cvedetails.com/) (SecurityScorecard (comercial))
- [MITRE CWE](https://cwe.mitre.org/) (MITRE)
- [MITRE ATT&CK](https://attack.mitre.org/) (MITRE)
- [INCIBE-CERT](https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades) (INCIBE (España))
- [CCN-CERT](https://www.ccn-cert.cni.es/es/seguridad-al-dia/vulnerabilidades.html) (CCN (España))
- [CCN-STIC 811 Interconexión en el ENS](https://www.ccn-cert.cni.es/series-ccn-stic/800-guia-esquema-nacional-de-seguridad/521-ccn-stic-811-interconexion-en-el-ens/file.html) (CCN (España))
- [CCN-STIC 816 Seguridad en redes inalámbricas en el ENS](https://www.ccn-cert.cni.es/pdf/guias/series-ccn-stic/guias-de-acceso-publico-ccn-stic/2317-ccn-stic-816-seguridad-en-redes-inalambricas-en-el-ens/file.html) (CCN (España))
- [Serie CCN-STIC 800 (guías del ENS, incluida la 812 de entornos y aplicaciones web)](https://www.ccn-cert.cni.es/gl/pdf/guias/series-ccn-stic.html) (CCN (España))
- [Real Decreto 311/2022 (ENS)](https://www.boe.es/buscar/act.php?id=BOE-A-2022-7191) (BOE (España))
- [Directiva (UE) 2022/2555 (NIS2)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) (EUR-Lex (UE))
