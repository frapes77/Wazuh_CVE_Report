# Wazuh CVE Report

Script Python che genera un **report PDF** con l'elenco dei dispositivi affetti da una specifica CVE, interrogando il **Wazuh Indexer** (OpenSearch) che alimenta il modulo *Vulnerability Detection* di **Wazuh 4.8+**.

Una volta ricevuta la notifica di una nuova CVE lo script è pensato per verificare se nella propria infrastruttura ci sono dispositivi affetti da tale CVE

Per ogni CVE indicata, il report mostra:
- un riquadro con il codice CVE, severity, CVSS score e descrizione della vulnerabilità;
- un riquadro con le **Recommended Actions**, integrate (quando disponibili) con i riferimenti ufficiali presi da [NVD](https://nvd.nist.gov/);
- una tabella con i dispositivi affetti: nome host, sistema operativo/pacchetto (`package.name`) e relativa versione (`package.version`).

## Requisiti

- Python 3.8+
- Un Wazuh Indexer (OpenSearch) raggiungibile in rete, versione Wazuh **4.8 o superiore** (il modulo di vulnerability detection deve scrivere sull'indice `wazuh-states-vulnerabilities-*`)
- Un utente con permessi di lettura su tale indice (tipicamente lo stesso account usato per il Wazuh Dashboard)
- Connessione a Internet (opzionale) per l'arricchimento dei dati da NVD

## Installazione

```bash
git clone <url-del-repo>
cd <cartella-repo>
pip install -r requirements.txt
```

`requirements.txt`:
```
requests
reportlab
```

## Utilizzo

```bash
python3 wazuh_cve_report.py CVE-2026-70347
```

Se non specifichi la CVE come argomento, lo script te la chiede a runtime. In ogni caso, ti verranno richieste interattivamente username e password del Wazuh Indexer (tramite `getpass`, quindi non visibili a schermo e non salvate da nessuna parte).

### Parametri disponibili

| Parametro       | Descrizione                                                                                   | Default                     |
|-----------------|------------------------------------------------------------------------------------------------|------------------------------|
| `cve`           | Codice CVE da cercare (posizionale, opzionale)                                                | richiesto a runtime se assente |
| `--host`        | URL del Wazuh Indexer                                                                          | `https://localhost:9200`     |
| `--output`      | Nome del file PDF generato                                                                     | `report_<CVE>.pdf`           |
| `--insecure`    | Disabilita la verifica del certificato SSL (utile con certificati self-signed)                | disabilitata di default già  |
| `--no-internet` | Non contattare NVD per arricchire descrizione/riferimenti, usa solo i dati presenti in Wazuh   | disattivato                   |
| `--agent`       | Filtra la ricerca su un singolo agent (per nome), utile per debug                              | nessun filtro                 |
| `--debug`       | Stampa informazioni diagnostiche (totale hit, query inviata) e salva la risposta grezza in `debug_response.json` | disattivato |

### Esempi

```bash
# Report standard
python3 wazuh_cve_report.py CVE-2026-70347 --host https://10.0.0.10:9200

# Verifica mirata su un singolo host, con output diagnostico
python3 wazuh_cve_report.py CVE-2026-70347 --agent XXXXXXX --debug

# Senza chiamare NVD (rete isolata / air-gapped)
python3 wazuh_cve_report.py CVE-2026-70347 --no-internet
```

## Come funziona

Lo script interroga l'indice `wazuh-states-vulnerabilities-*`, che rappresenta lo **stato attuale** dell'inventario vulnerabilità (l'ultima sincronizzazione per ogni agent), non uno storico di eventi. Questo significa che una CVE rilevata in passato ma nel frattempo risolta (es. pacchetto aggiornato) **non comparirà più** nel report, perché il dispositivo non risulta più vulnerabile alla data dell'interrogazione.

## Limitazioni note

- Pensato per **Wazuh 4.8+** (architettura basata su Indexer/OpenSearch). Sulle versioni precedenti (4.3–4.7), che usano il vecchio *Vulnerability Detector* via API Manager (porta 55000), la logica di query va adattata: non esiste una ricerca diretta per CVE su tutti gli host, va fatta agent per agent.
- La query usa `size: 1000`; con più di 1000 dispositivi affetti dalla stessa CVE andrebbe implementata la paginazione (`scroll` / `search_after`).
- I nomi dei campi (`package.name`, `package.version`) possono variare leggermente a seconda della versione esatta del mapping dell'indice Wazuh: se il PDF esce con colonne vuote, usa `--debug` per ispezionare `debug_response.json` e verificare i nomi effettivi dei campi.
- Il recupero dati da NVD è soggetto ai rate limit dell'API pubblica NVD; in caso di errore lo script prosegue comunque, usando solo i dati disponibili da Wazuh.

## Sicurezza

- Le credenziali dell'Indexer vengono richieste a runtime e non vengono mai salvate su disco né loggate.
- Di default la verifica del certificato SSL è disabilitata (`VERIFY_SSL = False`) per compatibilità con certificati self-signed tipici degli ambienti Wazuh on-premise. Se il tuo Indexer ha un certificato valido, imposta `VERIFY_SSL = True` in testa allo script.

## Licenza

Distribuito con licenza [MIT](LICENSE) (o quella che preferisci indicare).
