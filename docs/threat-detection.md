# Guía de Detección de Amenazas DNS

## ¿Qué detecta DNS Expert Monitor?

### 1. DNS Tunneling
**Descripción**: Técnica para evadir firewalls encapsulando datos en consultas DNS.

**Indicadores**:
- Dominios con alta entropía (>4.5)
- Subdominios excesivamente largos (>50 caracteres)
- Patrones Base64/Hexadecimal en nombres
- Tipos de registro inusuales (TXT, NULL, KEY)

**Ejemplo detectado**:
🚨 ALERTA: Alta entropía (4.62) en dominio: 23pzgde427i3ln7qmkdr986h4snnkt.example.com

### 2. DNS Poisoning/Cache Poisoning
**Descripción**: Inyección de registros DNS falsos en la cache.

**Indicadores**:
- TTL anormalmente bajos (<30 segundos)
- Múltiples respuestas diferentes para la misma consulta
- Respuestas de servidores no autorizados

**Ejemplo detectado**:
⚠️ ADVERTENCIA: TTL anormalmente bajo (5s) para main.vscode-cdn.net

### 3. Ataques de Amplificación DNS
**Descripción**: Ataques DDoS que usan servidores DNS para amplificar tráfico.

**Indicadores**:
- Alto ratio respuesta/consulta (>10:1)
- Tasas de consulta anómalas (>100 QPS)
- Consultas excesivas de tipo ANY

**Ejemplo detectado**:
⚠️ ADVERTENCIA: Alta tasa de consultas (924.2 QPS) desde 192.168.111.128


### 4. Ataques NXDOMAIN
**Descripción**: Inundación de respuestas NXDOMAIN para saturar servidores.

**Indicadores**:
- Alto porcentaje de respuestas NXDOMAIN (>30%)
- Tasa elevada de NXDOMAIN por minuto (>100)
- Subdominios aleatorios generados automáticamente

## Configuración Recomendada

### Para redes corporativas:
```
detectors:
  dns_tunneling:
    entropy_threshold: 4.3      # Más sensible
    max_subdomain_length: 40    # Más restrictivo
  
  poisoning_detector:
    min_ttl_for_alert: 60       # TTL mínimo aceptable
  
  amplification_detector:
    max_queries_per_second: 50  # Límite más bajo
  
  nxdomain_attack:
    nxdomain_percentage_threshold: 20  # Más sensible
```
### Para ISPs/Carriers:
```
detectors:
  amplification_detector:
    min_amplification_ratio: 5   # Más sensible a amplificación
    max_queries_per_second: 1000 # Límite más alto
  
  nxdomain_attack:
    nxdomain_per_minute_threshold: 500 # ISP escala mayor
```

## Mitigación Recomendada
Para DNS Tunneling:
- Implementar DNS filtering con listas de dominios permitidos
- Limitar longitud máxima de nombres de dominio
- Monitorear tipos de registro inusuales

## Para DNS Poisoning:
- Usar DNSSEC para validación criptográfica
- Configurar TTL mínimos apropiados
- Limitar servidores DNS autorizados

## Para Amplificación DDoS:
- Rate limiting en servidores DNS recursivos
- Deshabilitar o limitar consultas de tipo ANY
- Implementar Response Rate Limiting (RRL)

# Casos de Estudio

## Caso 1: Exfiltración de Datos
- Escenario: Empleado exfiltra datos corporativos vía DNS tunneling.
- Detección: Alertas de alta entropía y patrones Base64.
- Acción: Investigar IP origen y bloquear dominios sospechosos.

## Caso 2: Ataque DDoS a Infraestructura
- Escenario: Ataque de amplificación contra servidores web.
- Detección: Alertas de alto ratio y tasa de consultas.
- Acción: Implementar rate limiting y contactar ISP.

## Caso 3: Envenenamiento de Cache
- Escenario: Atacante redirige tráfico a servidores maliciosos.
- Detección: Alertas de TTL bajo y múltiples respuestas.
- Acción: Validar DNSSEC y purgar cache DNS.