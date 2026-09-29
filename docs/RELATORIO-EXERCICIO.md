# Relatório do exercício — MBA Engenharia DevOps

**Repositório:** github.com/juarezbamberg-source/metacortex-manifest · **Data:** 2026-09-29 · **Aplicação-alvo:** nyx-api

## 1. O problema

Recebi o *Padrão de Manifests da Metacortex* — o wiki interno de Plataforma que define como todo manifesto Kubernetes deve ser escrito no parque (blocos: identidade/nomenclatura, resiliência, segurança, vocabulário; níveis obrigatório/recomendado/proibido). O desafio: transformar um documento de revisão em **entrega automatizada** — manifests conformes, com a conformidade provada por pipeline, não por memória de revisor.

## 2. Metodologia aplicada

1. **Checklist primeiro** — cada regra do padrão virou uma linha "regra → como atendo" antes de qualquer YAML.
2. **Manifests com o checklist na mão** — nyx-api em YAML puro para dev/stg/prod, diferindo só nos pontos que o padrão prevê.
3. **Policy as code** — as regras da casa viraram script (`scripts/validar-regras-casa.py`), com a semântica do padrão: FALHA barra (obrigatório/proibido), aviso exige justificativa no PR (recomendado).
4. **Validação local antes do push** — as mesmas 3 camadas do CI, rodadas na máquina de desenvolvimento.
5. **Teste negativo** — fixture de propósito violando o padrão (camelCase, sem rótulos, `:latest`, senha em texto puro, seletor errado, targetPort órfão) para provar que o validador **barra** o que deve barrar.
6. **CI como gate de PR** — 3 camadas a cada Pull Request.
7. **CD com promoção por commit** — o mesmo SHA flui dev → stg → prod, com gate humano em prod.
8. **Documentação viva** — checklist de conformidade, runbook (o `metacortex.io/runbook` do padrão, materializado), ADRs.

## 3. O que foi entregue

| Componente | Descrição |
|---|---|
| `manifests/{dev,stg,prod}` | 6 objetos por ambiente (7 em prod, com PDB) + kustomization de aplicação |
| `scripts/validar-regras-casa.py` | 20+ regras da casa em Python — FALHA/aviso, saída por arquivo |
| `.github/workflows/validar-manifests.yml` | CI de PR: 3 camadas de validação |
| `.github/workflows/deploy.yml` | CD: validar → dev → stg → prod (gate de aprovação em prod) |
| `docs/RUNBOOK.md` | Procedimento de plantão: saúde, deploy, rollback, troubleshooting, segredos, escalação |
| `docs/DECISOES.md` | 8 ADRs das decisões de arquitetura e operação |
| `README.md` | Visão geral + checklist de conformidade regra a regra |

## 4. Resultados e provas

**Execuções do pipeline (2026-09-29):**

| Run | Gatilho | Resultado |
|---|---|---|
| 36612228707 | push main (CI) | ✅ success — 3 camadas verdes |
| 36618560221 | push main (badge) | ✅ success — badge "passing" |
| 36619625960 | push main (CD) | ✅ success — dev, stg e **prod aprovado pelo gate humano** |

**Provas de conformidade:**

- Camada 1: `0 falhas · 0 avisos` em 22 arquivos
- Camada 2 (kubeconform): `Valid: 19, Invalid: 0, Errors: 0` (3 Kustomizations puladas por design)
- Camada 3 (trivy): `0` misconfigurations HIGH/CRITICAL
- Teste negativo: fixture inválida barrada nas regras esperadas (1.1, 1.3, 3.1, 3.3, 4.5)
- Deploy de prod: 7 objetos aterrissados em cluster kind real, asserções de réplicas=2, PDB minAvailable=1, RollingUpdate maxUnavailable=0 — todas passaram

## 5. Lições aprendidas

1. **O padrão já contém a arquitetura da solução** — "a varredura com Trivy roda no pipeline" (Bloco 3) e `managed-by: platform` (Bloco 1) descrevem exatamente o CI/CD que o exercício pede. Ler o documento como especificação de sistema, não só de formato.
2. **Policy as code muda a natureza da revisão** — o PR passa a discutir exceção e contexto, não conformidade mecânica. É o que o próprio padrão diz querer: "que a revisão seja sobre o que importa".
3. **Teste negativo é o que dá autoridade ao validador** — um validador que nunca provou que barra não é gate, é sugestão.
4. **Gate humano em prod é processo, não burocracia** — a regra de réplicas ≥ 2 nasceu de um incidente; a aprovação em prod é o momento em que alguém assume a mudança.
5. **"Deploy" sem prova é narrativa** — as asserções pós-apply transformam "o pipeline passou" em "os objetos existem no cluster e conferem com o padrão".
6. **Ferramenta tem versão** — o primeiro run falhou por tag errada de action (`0.28.0` vs `v0.36.0`); o CI pegou em segundos. É o sistema funcionando, não falhando.

## 6. Próximos passos (evolução natural)

- **ArgoCD** sincronizando o repositório (o padrão já prevê `managed-by: argocd`) — diff contínuo entre Git e cluster.
- **Gestão de segredos** (External Secrets/SOPS) para eliminar o passo manual de segredo.
- **Policy engine** (OPA/Gatekeeper ou Kyverno) no cluster, complementando a validação estática no push.
- **Ambiente efêmero por PR** (preview environments) usando a mesma base de manifests.
