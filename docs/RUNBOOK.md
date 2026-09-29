# Runbook — nyx-api

Procedimento de plantão para a nyx-api nos ambientes `nyx-dev`, `nyx-stg` e `nyx-prod`. É o documento referenciado pela anotação `metacortex.io/runbook` do Deployment — em um parque real, esta URL apontaria para o wiki interno; neste repositório, ele vive aqui.

**Dono:** plataforma-nyx · **Escala de plantão:** Segurança & Compliance → Plataforma

## 1. Verificar saúde do workload

```bash
# estado geral do ambiente
kubectl -n nyx-prod get deploy,pods,svc,pdb

# rollout saudável? (todas as réplicas ready)
kubectl -n nyx-prod rollout status deployment/nyx-api

# o Service tem endpoints? (vazio = seletor não casa com os pods — regra 1.4)
kubectl -n nyx-prod get endpoints nyx-api
```

## 2. Deploy normal

1. Todo o deploy nasce de um **push na `main`** — não aplique manifest à mão (o Git é a fonte da verdade).
2. A esteira valida (3 camadas) e promove dev → stg → prod.
3. O prod **pausa no gate**: aprovar em *Actions → run → Review deployments → Approve and deploy*.
4. Confirmar: `kubectl -n nyx-prod rollout status deployment/nyx-api`.

## 3. Rollback

| Situação | Caminho | Comando |
|---|---|---|
| Mudança ruim identificada, sem pressa | **GitOps (normal)** | `git revert <commit> && git push` — a esteira reentrega pelos mesmos gates |
| Incidente ativo, conter primeiro | **Emergência** | `kubectl -n nyx-prod rollout undo deployment/nyx-api` |

> O rollback de emergência sai do controle de versão: depois de conter, **concilie o Git** (revert do commit) para o estado desejado voltar a ser o declarado.

## 4. Troubleshooting

| Sintoma | Causa provável | Ação |
|---|---|---|
| `ImagePullBackOff` | Imagem não existe no registry ou tag errada (regra 3.1 proíbe `:latest` justamente por isso) | Conferir `kubectl -n <ns> describe pod` → eventos; validar tag no registry |
| `CrashLoopBackOff` | Aplicação morrendo na inicialização — **o Pod continua em fase Running** (a falha vive no container) | `kubectl -n <ns> logs deploy/nyx-api --previous` |
| Service sem tráfego | `endpoints` vazio — seletor não casa com as labels do pod (erro nº 1 do parque, regra 1.4) | Comparar `spec.selector` do Service com as labels do template, caractere por caractere |
| `OOMKilled` reiniciando | Limit de memória apertado (regra 2.1: limit deve ser 1,5–2x o consumo em regime) | `kubectl -n <ns> top pods`; ajustar limit no manifest, por PR |
| Pod sai do balanceamento sem reiniciar | Readiness falhando (comportamento correto — regra 4.8) | Verificar dependências do `/readyz`; não "consertar" desligando a probe |
| App inteira reiniciando quando o banco fica lento | Liveness apontando para endpoint que checa banco | Separar liveness (`/healthz`) de readiness (`/readyz`) — regra 2.2 |

## 5. Segredos

- O Git contém apenas **placeholders** em `data` (base64) — regra 3.3.
- Rotação do `DATABASE_URL`: aplicar o novo valor **fora do Git** (`kubectl -n <ns> patch secret nyx-db -p '{"data":{"url":"<novo-base64>"}}'`) e reiniciar o workload (`kubectl -n <ns> rollout restart deployment/nyx-api`). A mudança no Secret **não** é versionada — registrar no canal do plantão.
- Secret do Kubernetes é base64, não criptografia: a proteção em repouso é do cluster.

## 6. Escalação

1. Verificar este runbook e os eventos do pod.
2. Acionar o dono (`metacortex.io/owner: plataforma-nyx`).
3. Incidente com impacto em cliente: abrir incidente com Segurança & Compliance — exceção a regra *proibida* não existe (padrão, seção Exceções).
