# metacortex-manifest

[![validar-manifests](https://github.com/juarezbamberg-source/metacortex-manifest/actions/workflows/validar-manifests.yml/badge.svg)](https://github.com/juarezbamberg-source/metacortex-manifest/actions/workflows/validar-manifests.yml)
[![deploy](https://github.com/juarezbamberg-source/metacortex-manifest/actions/workflows/deploy.yml/badge.svg)](https://github.com/juarezbamberg-source/metacortex-manifest/actions/workflows/deploy.yml)

Manifests Kubernetes da **nyx-api** conformes ao **Padrão de Manifests da Metacortex** — exercício prático do MBA em Engenharia DevOps.

**Documentação:** [Runbook operacional](docs/RUNBOOK.md) · [Registro de decisões (ADRs)](docs/DECISOES.md) · [Relatório do exercício](docs/RELATORIO-EXERCICIO.md)

## A ideia central

Conformidade a um padrão de manifests não pode depender da memória de quem revisa: **policy as code**. Cada PR passa por quatro camadas de validação no GitHub Actions:

| # | Camada | O que pega |
|---|--------|-----------|
| 0 | `pytest tests/` | Os testes do próprio validador (12 testes: base válida + uma violação por regra) — a camada que valida o validador |
| 1 | `scripts/validar-regras-casa.py` | As regras da casa que as ferramentas genéricas não conhecem: nomenclatura, rótulos obrigatórios, seletor × rótulos do pod, segredo em texto puro, securityContext, probes (incluindo porta não exposta pelo container), réplicas em prod, PDB, targetPort órfão |
| 2 | `kubeconform -strict` | O YAML contra o schema real da API do Kubernetes |
| 3 | `trivy config` | A varredura de má-configuração citada no Bloco 3 do padrão |

O script da camada 1 reproduz a semântica do padrão: **FALHA** para regra *obrigatória* ou *proibida* (barra o PR), **aviso** para regra *recomendada* (exige justificativa escrita no PR).

## Estrutura

```
metacortex-manifest/
├── .github/
│   ├── dependabot.yml          # updates semanais das actions
│   └── workflows/
│       ├── validar.yml         # workflow reutilizável: testes + 3 camadas
│       ├── validar-manifests.yml  # CI de PR (chama validar.yml)
│       └── deploy.yml          # CD: validar → dev → stg → prod (gate em prod)
├── scripts/
│   └── validar-regras-casa.py  # regras da casa (policy as code)
├── tests/
│   └── test_validador.py       # 12 testes do validador (camada 0 do CI)
├── docs/
│   ├── RUNBOOK.md              # procedimento de plantão (o runbook do padrão)
│   ├── DECISOES.md             # ADRs — decisões e porquês
│   └── RELATORIO-EXERCICIO.md  # metodologia, provas e lições (MBA)
├── manifests/
│   ├── dev/    # nyx-dev  — 1 réplica, sem PDB
│   ├── stg/    # nyx-stg  — 1 réplica, sem PDB
│   └── prod/   # nyx-prod — 2 réplicas, RollingUpdate sem queda, PDB
└── LICENSE                     # MIT
```

Cada ambiente contém: `namespace`, `serviceaccount`, `configmap`, `secret`, `deployment`, `service` (+ `pdb` em prod) e um `kustomization.yaml` com a ordem de aplicação. YAML puro de propósito: cada objeto fica visível, sem camadas de template — a diferença entre ambientes é exatamente a que o padrão prevê.

## Diferenças entre ambientes (e só elas)

| Regra | dev | stg | prod |
|-------|-----|-----|------|
| 2.3 Réplicas | 1 | 1 | **2** |
| 2.4 RollingUpdate (maxUnavailable: 0) | — | — | **sim** |
| 2.5 PodDisruptionBudget | — | — | **sim** (minAvailable: 1) |
| 1.2 Namespace | nyx-dev | nyx-stg | nyx-prod |
| Valores de ConfigMap/Secret | por ambiente | por ambiente | por ambiente |

## Checklist de conformidade

### Bloco 1 — Identidade e nomenclatura

| Regra | Nível | Como atende |
|-------|-------|-------------|
| 1.1 Nome em kebab-case | obrigatório | `nyx-api`, `nyx-db` — sem camelCase/underscore |
| 1.2 Namespace `<cliente>-<ambiente>` | obrigatório | `nyx-dev`, `nyx-stg`, `nyx-prod` |
| 1.3 Quatro rótulos obrigatórios | obrigatório | `app.kubernetes.io/name`, `instance`, `part-of`, `managed-by` em todo objeto |
| 1.4 Seletor casa com rótulos do pod | obrigatório | Seletor do Service e matchLabels do Deployment idênticos às labels do template — verificado por script |
| 1.5 Anotação de dono | recomendado | `metacortex.io/owner: plataforma-nyx` + `metacortex.io/runbook` no Deployment |
| 1.6 Container com nome do componente | recomendado | container `api` |

### Bloco 2 — Resiliência

| Regra | Nível | Como atende |
|-------|-------|-------------|
| 2.1 Requests e limits | obrigatório | CPU `100m/500m`, memória `128Mi/512Mi` (limit ~2x o request, bolso da casa) |
| 2.2 Probes obrigatórias | obrigatório | readiness `/readyz` e liveness `/healthz` — endpoints distintos, como manda o padrão |
| 2.3 Réplicas ≥ 2 em prod | obrigatório | `replicas: 2` em prod; 1 em dev/stg é aceitável |
| 2.4 Estratégia de atualização | obrigatório (prod) | `RollingUpdate` com `maxUnavailable: 0, maxSurge: 1` |
| 2.5 PodDisruptionBudget | recomendado (prod) | PDB com `minAvailable: 1` |
| 2.6 Grace period compatível | recomendado | `terminationGracePeriodSeconds: 40` |

### Bloco 3 — Segurança

| Regra | Nível | Como atende |
|-------|-------|-------------|
| 3.1 Tag `:latest` proibida | proibido | `registry.metacortex.io/nyx/api:2.9.1` — tag imutável |
| 3.2 securityContext | obrigatório | `runAsNonRoot`, `runAsUser: 10001`, sem escalonamento, rootfs só-leitura, `drop: ["ALL"]`; `/tmp` via `emptyDir` |
| 3.3 Segredo em texto puro proibido | proibido | `DATABASE_URL` por `secretKeyRef`; Secret versionado só com placeholder em `data` (base64) — valor real aplicado fora do Git |
| 3.4 `automountServiceAccountToken: false` | obrigatório | no Pod e na ServiceAccount |
| 3.5 ServiceAccount dedicada | recomendado | `nyx-api`, sem RBAC (não fala com a API) |
| 3.6 hostNetwork/hostPID/privileged | proibido | ausentes |
| 3.7 Só registry interno | obrigatório | `registry.metacortex.io` em toda imagem |

### Bloco 4 — Vocabulário

Os conceitos (Pod, ReplicaSet, Deployment, Service, port × targetPort, Endpoints, ConfigMap/Secret, probes) estão comentados **dentro de cada YAML**, no ponto onde aparecem — e a regra 4.5 (`targetPort` tem que apontar para porta que o container escuta) é checada pelo script.

## Validar localmente

Requisitos: Python 3.10+ com `pyyaml` e `pytest` (`pip install pyyaml pytest`), [kubeconform](https://github.com/yannh/kubeconform) e [trivy](https://trivy.dev) no PATH.

```bash
# camada 0 — testes do validador
python -m pytest tests/ -q

# camada 1 — regras da casa
python scripts/validar-regras-casa.py manifests

# camada 2 — schema
kubeconform -strict -summary -ignore-missing-schemas manifests/

# camada 3 — varredura de má-configuração
trivy config --severity HIGH,CRITICAL --exit-code 1 manifests/
```

## Entrega contínua

O workflow `deploy.yml` roda a cada push na `main` que toque os manifests e promove **o mesmo commit** pelos três ambientes — o commit é a unidade de promoção:

```
push na main
   │
   ▼
[validar]      3 camadas de validação (o mesmo gate do PR)
   │
   ▼
[deploy-dev]   environment dev   → cluster kind efêmero + kubectl apply -k manifests/dev
   │
   ▼
[deploy-stg]   environment stg   → automático após dev
   │
   ▼
[deploy-prod]  environment prod  → ⏸ pausa e aguarda aprovação na UI do GitHub
                                   (revisor obrigatório configurado no environment)
```

- **Gate de produção**: o environment `prod` tem revisor obrigatório — o job pausa em "Waiting for review" até alguém aprovar em *Actions → run → Review deployments*. É o mecanismo nativo do GitHub para gate de produção.
- **Prova de deploy**: cada ambiente aplica num cluster kind efêmero e verifica a aterrissagem dos objetos (`kubectl get`) e as regras que diferem por ambiente — réplicas (2.3), PDB só em prod (2.5), rollout strategy (2.4). Os Pods ficam `ImagePullBackOff` por design: `registry.metacortex.io` é o registry fictício do padrão; num parque real, este seria o momento do `kubectl rollout status`.
- **Concorrência**: deploys são serializados (`concurrency`) — dois pushes na main não deployam em paralelo.

### Rollback

- **Caminho normal (GitOps)**: `git revert` do commit que introduziu a mudança + push na `main` — a esteira reentrega o estado anterior pelos mesmos gates.
- **Emergência (imperativo, documentado no runbook)**: `kubectl rollout undo deployment/nyx-api -n <ambiente>` — mais rápido, porém fora do controle de versão; usar só para conter incidente, conciliando o Git em seguida.

### Em um cluster real

O apply usaria credencial por ambiente (OIDC federado ou secret protegido) em vez de cluster efêmero, e a evolução natural é um GitOps controller (o padrão já prevê `managed-by: argocd`) sincronizando este repositório.

## Governança do repositório

- **Branch protection na `main`**: todo change entra por **Pull Request**, com o status check "Validar manifests / Regras da casa + schema + trivy" obrigatório, `strict` (branch atualizada antes do merge), sem force push e com `enforce_admins` — vale até para administradores.
- **Dependabot**: updates semanais das actions do pipeline (PRs `chore(deps)`), mesclados pelo mesmo fluxo de PR.
- **Release**: `v1.0.0` taggeada no commit da auditoria — o padrão prega tag imutável, o repo pratica.

## Aplicar

```bash
kubectl apply -k manifests/dev    # ou stg / prod
```

> Os Secrets versionados contêm **placeholders**. O valor real de `DATABASE_URL` é aplicado fora do Git (regra 3.3) — por quem opera o cluster, via pipeline de deploy ou ferramenta de gestão de segredos.
