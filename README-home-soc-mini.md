# Home SOC Mini — Suricata + Elasticsearch + Kibana

Laboratorio casero de detección de intrusos (IDS) con visualización de alertas en tiempo real, simulando un mini SOC (Security Operations Center). Construido de cero, incluyendo el proceso real de troubleshooting de una implementación en producción a pequeña escala.

## Arquitectura

- **VM Sensor** (Ubuntu Server 26.04, 6GB RAM): Suricata (IDS) + Filebeat + Elasticsearch + Kibana
- **VM Víctima**: Metasploitable2 (`192.168.6.132`)
- **VM Atacante**: Kali Linux (`192.168.6.130`)

Todas las VMs corriendo en VMware Workstation, conectadas en la misma red virtual (`192.168.6.0/24`), permitiendo que el Sensor capture el tráfico entre Atacante y Víctima en modo promiscuo vía `af-packet`.

## Stack utilizado

| Componente | Función | Versión |
|---|---|---|
| Suricata | Motor IDS, detección de firmas de ataque | Última estable (apt) |
| Filebeat | Envío de logs de Suricata a Elasticsearch (módulo `suricata`, fileset `eve`) | 8.19.19 |
| Elasticsearch | Almacenamiento e indexación de alertas | 8.19.19 |
| Kibana | Visualización, dashboards y Discover | 8.19.19 |

## Instalación (resumen)

1. Suricata instalado vía apt, configurado en modo `af-packet` sobre la interfaz `ens33`, con reglas actualizadas vía `suricata-update` (52,103 reglas cargadas).
2. Elasticsearch + Kibana instalados desde el repositorio oficial de Elastic, con seguridad y certificados autofirmados habilitados por defecto.
3. Filebeat configurado con el módulo `suricata` (fileset `eve`) apuntando a `/var/log/suricata/eve.json`, con salida hacia Elasticsearch vía HTTPS.

## Problemas reales encontrados y solución

Este proyecto se documentó incluyendo los errores reales del proceso, ya que el troubleshooting es parte central del aprendizaje en ciberseguridad/redes:

| Problema | Causa | Solución |
|---|---|---|
| `Error: Valor establecido inválido para Signed-By` al agregar el repo de Elastic | La descarga de la key GPG falló silenciosamente por un problema previo de DNS, dejando el archivo vacío/corrupto | Se regeneró la key con `wget` una vez resuelto el DNS |
| `OOM Kill` — Elasticsearch se caía solo tras iniciar | La VM tenía solo 3.3GB de RAM sin swap; Elasticsearch reservaba más heap del disponible | Se limitó el heap a `-Xms1g -Xmx1g` vía `jvm.options.d/heap.options`, se subió la RAM de la VM a 6GB y se agregó 2GB de swap |
| Kibana no cargaba en el navegador del host | `server.host` estaba en `127.0.0.1` por defecto (solo accesible desde dentro de la VM) | Se cambió a `server.host: "0.0.0.0"` en `kibana.yml` |
| Filebeat en loop de reinicio (`exit-code 1`) | El fileset `eve` del módulo `suricata` estaba declarado pero no habilitado (`enabled: false`) | Se corrigió `/etc/filebeat/modules.d/suricata.yml` con `enabled: true` |
| Hydra fallaba con error de negociación SSH (`no matching host key type`, `kex error`) | Metasploitable2 usa una versión de OpenSSH muy antigua (2010) que solo soporta algoritmos legacy (`ssh-rsa`, `diffie-hellman-group1-sha1`) ya deshabilitados en clientes modernos | Se forzaron los algoritmos legacy en `/etc/ssh/ssh_config` para permitir la conexión de prueba manual |
| **Suricata no generaba ninguna alerta de SSH pese a que el ataque funcionaba** | `HOME_NET` estaba configurado como toda la subred `192.168.6.0/24`, incluyendo tanto a Kali como a Metasploitable. Las reglas de detección de SSH scan/bruteforce del ruleset base solo se disparan para tráfico `$EXTERNAL_NET → $HOME_NET`; al estar ambos hosts en la misma red "interna", Suricata nunca las consideraba tráfico sospechoso | Se acotó `HOME_NET` a solo la IP de la víctima (`192.168.6.132/32`), simulando que Metasploitable es la red protegida y todo lo demás (incluido Kali) es tráfico externo |
| Las alertas SSH no aparecían en el dashboard predefinido de Kibana pese a existir en Elasticsearch | El dashboard `[Filebeat Suricata] Alert Overview` no mostraba eventos con pocos hits, posiblemente por agregación tipo "top N" o filtro guardado | Se verificó directamente con la API de Elasticsearch (`_search`) y con **Kibana Discover**, confirmando que el dato sí estaba indexado correctamente bajo `rule.id` |

## Ataques ejecutados y detección confirmada

| # | Ataque | Herramienta | Regla / Alerta Suricata | Rule ID | Severidad |
|---|---|---|---|---|---|
| 1 | Escaneo de reconocimiento | Nmap (`-sS -A`) | ET SCAN Possible... (Web Application Attack) | — | Media |
| 2 | Fuerza bruta SSH (intento 1) | Hydra | ET SCAN Potential SSH Scan | 2001219 | Media |
| 3 | Fuerza bruta SSH (intento 2, ráfaga de conexiones) | Hydra (`-t 16`) | ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack | 2006546 | Alta (Attempted Administrator Privilege Gain) |

Credencial objetivo: `msfadmin:msfadmin` (default documentada de Metasploitable2). Verificado tanto en el log crudo (`eve.json`) como en Elasticsearch (`_search` API) y en Kibana Discover.

## Evidencias

*(agregar aquí tus capturas de pantalla guardadas en `docs/screenshots/`)*

- `docs/screenshots/nmap-scan-terminal.png` — ataque Nmap ejecutado desde Kali
- `docs/screenshots/hydra-ssh-success.png` — Hydra encontrando la credencial válida
- `docs/screenshots/kibana-events-overview.png` — dashboard general mostrando 2,374+ eventos capturados
- `docs/screenshots/kibana-alert-overview.png` — top de firmas de alerta detectadas
- `docs/screenshots/discover-ssh-bruteforce.png` — verificación en Discover de la alerta `rule.id: 2006546`

## Hallazgos y aprendizajes clave

1. **La segmentación de `HOME_NET` es crítica.** Un IDS mal configurado con una definición de red demasiado amplia puede volverse ciego a ataques laterales dentro de la misma subred — un hallazgo directamente aplicable a redes corporativas segmentadas.
2. **Los dashboards predefinidos no reemplazan la verificación directa de datos.** Kibana Discover y la API de Elasticsearch fueron más confiables que el dashboard visual para confirmar la existencia real de una alerta.
3. **El ruleset base de Suricata (Emerging Threats) requiere tuning.** Muchas reglas (como las de brute-force) tienen umbrales (`threshold: count 5, seconds 30`) que exigen patrones de tráfico específicos — un ataque "silencioso" o con pocos intentos puede pasar desapercibido.
4. **Los recursos de hardware importan tanto como la configuración.** El heap de Elasticsearch y la RAM total de la VM fueron la causa raíz de la inestabilidad inicial del stack — dimensionar correctamente es parte del diseño, no un detalle menor.

## Próximos pasos (mejoras futuras)

- Agregar el tercer vector de ataque (explotación de vsftpd backdoor) para ampliar la cobertura de detección
- Correlacionar alertas de Suricata con logs de firewall/iptables
- Automatizar respuesta ante alertas críticas (ej. bloqueo automático de IP con un script que consuma la API de Elasticsearch)
- Escribir reglas custom de Suricata ajustadas a este entorno específico

## Autor

Adrian — Estudiante de Ingeniería en Conectividad y Redes, Duoc UC
