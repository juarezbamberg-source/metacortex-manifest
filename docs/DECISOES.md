# Registro de Decisões (ADRs)

Decisões de arquitetura e operação deste repositório, no formato leve: contexto → decisão → consequência. Cada uma pode ser desafiada por PR — o registro existe para a discussão ser sobre o que importa.

## ADR-001 — YAML puro, sem templates

**Contexto:** o padrão precisa ser legível para quem está chegando (Bloco 4 existe por causa do onboarding). Helm e Kustomize com overlays escondem o objeto final atrás de templates.
**Decisão:** manifests em YAML puro por ambiente; `kustomization.yaml` apenas como lista de aplicação (`kubectl apply -k`), sem transformação.
**Consequência:** repetição controlada entre ambientes (aceita — a diferença entre eles é pequena e explícita); qualquer pessoa lê o YAML e vê exatamente o que roda.

## ADR-002 — Validação em três camadas

**Contexto:** nenhuma ferramenta sozinha cobre o padrão. Trivy conhece misconfig genérica, kubeconform conhece o schema da API, e as regras da casa (kebab-case, 4 rótulos, seletor × template, namespace `<cliente>-<ambiente>`, `:latest`, segredo em texto puro, réplicas/rollout/PDB por ambiente) são específicas da Metacortex.
**Decisão:** camada 1 = `scripts/validar-regras-casa.py` (policy as code, com FALHA/aviso reproduzindo obrigatório/recomendado), camada 2 = kubeconform `-strict`, camada 3 = trivy config. Roda no CI de todo PR e no início de todo deploy.
**Consequência:** a revisão humana discute exceção, não conformidade; falsos positivos do script são corrigidos com PR no próprio script (ele também é código revisado).

## ADR-003 — Segredos: placeholder no Git, valor real fora

**Contexto:** regra 3.3 proíbe valor sensível em manifesto; o repositório é público.
**Decisão:** `Secret.data` com placeholder base64; o valor real é aplicado fora do Git, por quem opera (ou ferramenta de gestão de segredos).
**Consequência:** o apply de um ambiente novo exige o passo manual de segredo — documentado no runbook; rotação de segredo não passa por PR (trade-off consciente).

## ADR-004 — CD aplica em cluster kind efêmero com asserções

**Contexto:** `registry.metacortex.io` é fictício; não há cluster do parque para este exercício. "Deploy" precisa de prova, não de fé.
**Decisão:** cada job de ambiente sobe um cluster kind no runner, aplica com `kubectl apply -k` e verifica por asserções: objetos existem, réplicas conferem (2.3), PDB só em prod (2.5), rollout strategy (2.4).
**Consequência:** Pods ficam `ImagePullBackOff` por design (imagem fictícia) — a prova entregue é da aterrissagem dos objetos no API server, não da saúde da aplicação; em cluster real, o passo extra é `rollout status`.

## ADR-005 — Gate de produção via GitHub Environments

**Contexto:** produção exige aprovação humana (regra 2.3 nasceu de incidente; mudança em prod não pode ser automática).
**Decisão:** environments `dev`, `stg` e `prod` no GitHub; `prod` com revisor obrigatório. O job pausa até aprovação na UI.
**Consequência:** o gate é nativo da plataforma (sem ferramenta extra), auditável no run do Actions; quem aprova precisa de permissão no environment.

## ADR-006 — O commit é a unidade de promoção

**Contexto:** gerar manifests diferentes por ambiente no caminho (rebuild, re-tag) quebra a rastreabilidade "o que está em prod?".
**Decisão:** o mesmo SHA validado flui dev → stg → prod; os ambientes diferem só nos pontos previstos pelo padrão.
**Consequência:** responder "o que roda em prod" é `git log` + gate aprovado; não existe "funcionava no meu deploy".

## ADR-007 — Rollback: Git revert como caminho normal

**Contexto:** `rollout undo` é rápido mas imperativo — o Git deixaria de dizer a verdade sobre o cluster.
**Decisão:** caminho normal é `git revert` + push (a esteira reentrega pelos gates); `rollout undo` fica documentado no runbook como recurso de emergência para conter incidente, com conciliação do Git em seguida.
**Consequência:** contenção rápida é possível sem abrir exceção ao processo; o estado desejado volta a ser o declarado.

## ADR-008 — Probes em endpoints distintos

**Contexto:** o padrão alerta que liveness apontando para checagem de banco derruba a aplicação em cascata quando o banco fica lento.
**Decisão:** readiness em `/readyz` (posso receber tráfego?) e liveness em `/healthz` (estou vivo?), com `initialDelaySeconds` diferentes.
**Consequência:** falha de dependência tira o pod do balanceamento sem reiniciá-lo; o validador da camada 1 emite aviso quando as duas probes apontam para o mesmo endpoint.
