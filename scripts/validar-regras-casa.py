#!/usr/bin/env python3
"""Valida os manifests contra as regras da casa do Padrão de Manifests da Metacortex.

Este script é a 3ª camada de validação do repositório:
  1. kubeconform — valida o YAML contra o schema da API do Kubernetes;
  2. trivy config — varredura de má-configuração citada no Bloco 3 do padrão;
  3. este script — regras da casa que as ferramentas acima não conhecem
     (nomenclatura, rótulos obrigatórios, seletor x rótulos do pod,
      segredo em texto puro, securityContext, probes, réplicas...).

Níveis de saída:
  FALHA — regra obrigatória ou proibida violada: barra o PR (exit 1).
  AVISO — regra recomendada não atendida: precisa de justificativa escrita no PR.

Uso: python scripts/validar-regras-casa.py [DIR_MANIFESTS]   (padrão: manifests)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

# --- Regras da casa ---------------------------------------------------------

LABELS_OBRIGATORIOS = (
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/part-of",
    "app.kubernetes.io/managed-by",
)
AMBIENTES = ("dev", "stg", "prod")
REGISTRY_INTERNO = "registry.metacortex.io"
KEBAB_CASE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
NS_FORMATO = re.compile(r"^[a-z0-9]+-(dev|stg|prod)$")
NOMES_CONTAINER_RUINS = {"app", "main", "container"}
KINDS_CLUSTER = {"Namespace"}
PADROES_SEGREDO = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"postgres(ql)?://",
        r"mysql://",
        r"mongodb(\+srv)?://",
        r"redis://",
        r"password\s*=",
        r"passwd",
        r"senha\s*=",
        r"api[_-]?key\s*=",
        r"BEGIN [A-Z ]*PRIVATE KEY",
        r"AKIA[0-9A-Z]{16}",
    )
)

FALHA = "FALHA"
AVISO = "AVISO"


class Achado:
    """Resultado de uma verificação: nível, regra do padrão e mensagem."""

    def __init__(self, nivel: str, regra: str, msg: str):
        self.nivel = nivel
        self.regra = regra
        self.msg = msg


def checar_imagem(imagem: str) -> list[Achado]:
    """3.1 (tag :latest proibida) e 3.7 (só registry interno)."""
    a: list[Achado] = []
    if not imagem:
        return [Achado(FALHA, "3.1", "container sem imagem")]
    if "/" not in imagem:
        a.append(Achado(FALHA, "3.7", f'imagem "{imagem}" sem registry — só {REGISTRY_INTERNO} é permitido'))
    else:
        registry = imagem.split("/", 1)[0]
        if registry != REGISTRY_INTERNO:
            a.append(Achado(FALHA, "3.7", f'registry "{registry}" não é o interno ({REGISTRY_INTERNO})'))
    if "@" in imagem:
        return a  # digest — imutável, atende 3.1
    ultimo = imagem.rsplit("/", 1)[-1]
    if ":" not in ultimo:
        a.append(Achado(FALHA, "3.1", f'imagem "{imagem}" sem tag — use tag imutável ou digest'))
    elif ultimo.rsplit(":", 1)[1] == "latest":
        a.append(Achado(FALHA, "3.1", 'tag :latest é proibida — use tag imutável ou digest'))
    return a


def checar_container(cont: dict) -> list[Achado]:
    """Regras de container: 1.6, 2.1, 2.2, 3.1, 3.2, 3.3, 3.6, 3.7."""
    a: list[Achado] = []
    nome = cont.get("name") or ""
    if nome in NOMES_CONTAINER_RUINS:
        a.append(Achado(AVISO, "1.6", f'container chamado "{nome}" — use o nome do componente (api, worker...)'))

    a += checar_imagem(cont.get("image") or "")

    # 2.1 — requests e limits de CPU e memória
    recursos = cont.get("resources") or {}
    requests = recursos.get("requests") or {}
    limits = recursos.get("limits") or {}
    for campo in ("cpu", "memory"):
        if campo not in requests:
            a.append(Achado(FALHA, "2.1", f'container "{nome}" sem request de {campo}'))
        if campo not in limits:
            a.append(Achado(FALHA, "2.1", f'container "{nome}" sem limit de {campo}'))

    # 2.2 — probes obrigatórias e em endpoints distintos
    readiness = cont.get("readinessProbe")
    liveness = cont.get("livenessProbe")
    if not readiness:
        a.append(Achado(FALHA, "2.2", f'container "{nome}" sem readinessProbe'))
    if not liveness:
        a.append(Achado(FALHA, "2.2", f'container "{nome}" sem livenessProbe'))
    if readiness and liveness:
        get_r = readiness.get("httpGet") or {}
        get_l = liveness.get("httpGet") or {}
        if get_r and get_l and get_r.get("path") == get_l.get("path") and get_r.get("port") == get_l.get("port"):
            a.append(Achado(AVISO, "2.2", "readiness e liveness apontam para o mesmo endpoint — risco conhecido de derrubada em cascata"))

    # 3.2 — securityContext do container
    ctx = cont.get("securityContext") or {}
    if ctx.get("allowPrivilegeEscalation") is not False:
        a.append(Achado(FALHA, "3.2", f'container "{nome}" sem allowPrivilegeEscalation: false'))
    if ctx.get("readOnlyRootFilesystem") is not True:
        a.append(Achado(FALHA, "3.2", f'container "{nome}" sem readOnlyRootFilesystem: true'))
    drops = (ctx.get("capabilities") or {}).get("drop") or []
    if "ALL" not in drops:
        a.append(Achado(FALHA, "3.2", f'container "{nome}" sem capabilities.drop: ["ALL"]'))

    # 3.6 — privileged proibido
    if ctx.get("privileged"):
        a.append(Achado(FALHA, "3.6", f'container "{nome}" privileged: true é proibido'))

    # 3.3 — segredo em texto puro no env
    for ev in cont.get("env") or []:
        if "value" in ev:
            valor = str(ev["value"])
            if any(p.search(valor) for p in PADROES_SEGREDO):
                a.append(Achado(FALHA, "3.3", f'env "{ev.get("name")}" com valor sensível em texto puro — use secretKeyRef'))
    return a


def checar_deployment(doc: dict, ambiente: str | None) -> list[Achado]:
    """Regras de Deployment: 1.3/1.4 (template), 2.3, 2.4, 2.6, 3.2, 3.4, 3.5, 3.6."""
    a: list[Achado] = []
    spec = doc.get("spec") or {}

    # 2.3 — replicas >= 2 em prod
    replicas = spec.get("replicas", 1)
    if ambiente == "prod" and replicas < 2:
        a.append(Achado(FALHA, "2.3", f"prod com {replicas} réplica(s) — mínimo 2"))

    # 2.4 — estratégia de atualização em prod
    if ambiente == "prod":
        estrategia = spec.get("strategy") or {}
        if estrategia.get("type") != "RollingUpdate":
            a.append(Achado(FALHA, "2.4", "prod sem strategy RollingUpdate"))
        else:
            mu = (estrategia.get("rollingUpdate") or {}).get("maxUnavailable")
            if not (mu == 0 or mu == "0" or mu == "0%"):
                a.append(Achado(FALHA, "2.4", "prod com maxUnavailable != 0 — capacidade cai durante o rollout"))

    # 1.4 — matchLabels do Deployment dentro das labels do template
    template_meta = ((spec.get("template") or {}).get("metadata") or {})
    labels_template = template_meta.get("labels") or {}
    match_labels = (spec.get("selector") or {}).get("matchLabels") or {}
    if not match_labels:
        a.append(Achado(FALHA, "1.4", "Deployment sem selector.matchLabels"))
    for chave, valor in match_labels.items():
        if labels_template.get(chave) != valor:
            a.append(Achado(FALHA, "1.4", f'selector "{chave}: {valor}" não casa com as labels do template do pod'))
    faltando_template = [r for r in LABELS_OBRIGATORIOS if r not in labels_template]
    if faltando_template:
        a.append(Achado(FALHA, "1.3", f"template do pod sem os rótulos obrigatórios: {', '.join(faltando_template)}"))

    podspec = (spec.get("template") or {}).get("spec") or {}

    # 3.4 — automountServiceAccountToken: false
    if podspec.get("automountServiceAccountToken") is not False:
        a.append(Achado(FALHA, "3.4", "automountServiceAccountToken não é false — token da API exposto sem necessidade"))

    # 3.5 — ServiceAccount dedicada (recomendado)
    sa = podspec.get("serviceAccountName")
    if not sa or sa == "default":
        a.append(Achado(AVISO, "3.5", "sem ServiceAccount dedicada (usa default ou nenhuma)"))

    # 2.6 — terminationGracePeriodSeconds declarado (recomendado)
    if "terminationGracePeriodSeconds" not in podspec:
        a.append(Achado(AVISO, "2.6", "terminationGracePeriodSeconds não declarado"))

    # 3.6 — hostNetwork / hostPID / hostIPC proibidos
    for chave in ("hostNetwork", "hostPID", "hostIPC"):
        if podspec.get(chave):
            a.append(Achado(FALHA, "3.6", f"{chave}: true é proibido em workload de cliente"))

    # 3.2 — securityContext do pod
    pctx = podspec.get("securityContext") or {}
    if pctx.get("runAsNonRoot") is not True:
        a.append(Achado(FALHA, "3.2", "pod sem runAsNonRoot: true"))
    if pctx.get("runAsUser") is None:
        a.append(Achado(FALHA, "3.2", "pod sem runAsUser definido"))

    for cont in podspec.get("containers") or []:
        a += checar_container(cont)
    return a


def checar_configmap(doc: dict) -> list[Achado]:
    """3.3 — nenhum valor sensível em ConfigMap."""
    a: list[Achado] = []
    dados = doc.get("data") or {}
    for chave, valor in dados.items():
        if any(p.search(str(valor)) for p in PADROES_SEGREDO):
            a.append(Achado(FALHA, "3.3", f'ConfigMap "{doc.get("metadata", {}).get("name")}" chave "{chave}" com valor sensível'))
    return a


def checar_secret(doc: dict) -> list[Achado]:
    """3.3 — segredo em texto puro proibido; data (base64) é o formato aceito."""
    a: list[Achado] = []
    if doc.get("stringData"):
        a.append(Achado(FALHA, "3.3", 'Secret com stringData (texto puro versionado) — use data (base64) e aplique o valor real fora do Git'))
    return a


def validar_objeto(doc: dict, ambiente: str | None) -> list[Achado]:
    """Checagens por objeto, independentes de outros arquivos."""
    a: list[Achado] = []
    kind = doc.get("kind")
    meta = doc.get("metadata") or {}
    nome = meta.get("name") or ""
    rotulos = meta.get("labels") or {}
    namespace = meta.get("namespace")
    anotacoes = meta.get("annotations") or {}

    if not kind:
        return [Achado(FALHA, "estrutura", "objeto sem kind")]
    if kind == "Kustomization":
        return []  # documento de build do Kustomize, não é objeto de cluster

    # 1.1 — nome em kebab-case
    if not KEBAB_CASE.match(nome):
        a.append(Achado(FALHA, "1.1", f'nome "{nome}" fora de kebab-case'))

    # 1.2 — namespace <cliente>-<ambiente>
    if kind in KINDS_CLUSTER:
        if not NS_FORMATO.match(nome):
            a.append(Achado(FALHA, "1.2", f'namespace "{nome}" fora do formato <cliente>-<ambiente>'))
        if ambiente and nome != f"nyx-{ambiente}":
            a.append(Achado(FALHA, "1.2", f'namespace "{nome}" não corresponde ao diretório "{ambiente}"'))
    else:
        if namespace is None:
            a.append(Achado(FALHA, "1.2", "objeto namespaced sem namespace declarado"))
        else:
            if not NS_FORMATO.match(namespace):
                a.append(Achado(FALHA, "1.2", f'namespace "{namespace}" fora do formato <cliente>-<ambiente>'))
            if ambiente and namespace != f"nyx-{ambiente}":
                a.append(Achado(FALHA, "1.2", f'namespace "{namespace}" não corresponde ao diretório "{ambiente}"'))

    # 1.3 — quatro rótulos obrigatórios
    faltando = [r for r in LABELS_OBRIGATORIOS if r not in rotulos]
    if faltando:
        a.append(Achado(FALHA, "1.3", f"rótulos obrigatórios ausentes: {', '.join(faltando)}"))

    # 1.5 — anotação de dono (recomendado)
    if "metacortex.io/owner" not in anotacoes:
        a.append(Achado(AVISO, "1.5", "anotação metacortex.io/owner ausente"))

    if kind == "Deployment":
        a += checar_deployment(doc, ambiente)
    elif kind == "ConfigMap":
        a += checar_configmap(doc)
    elif kind == "Secret":
        a += checar_secret(doc)
    return a


def cruzar_diretorio(pares: list, ambiente: str | None) -> list[tuple[Path, Achado]]:
    """Checagens que cruzam arquivos do mesmo diretório: Service x Deployment (1.4) e PDB (2.5)."""
    a: list[tuple[Path, Achado]] = []
    deployments = [(f, d) for f, d in pares if d.get("kind") == "Deployment"]
    services = [(f, s) for f, s in pares if s.get("kind") == "Service"]
    pdbs = [(f, p) for f, p in pares if p.get("kind") == "PodDisruptionBudget"]

    def template_labels(dep: dict) -> dict:
        return (((dep.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels") or {}

    # 1.4 — seletor do Service tem que casar com os rótulos do pod
    for arquivo, serv in services:
        spec = serv.get("spec") or {}
        seletor = spec.get("selector") or {}
        ns_serv = (serv.get("metadata") or {}).get("namespace")
        if not seletor:
            a.append((arquivo, Achado(FALHA, "1.4", "Service sem selector — não entrega tráfego para nenhum pod")))
            continue
        alvo = None
        for arquivo_dep, dep in deployments:
            if (dep.get("metadata") or {}).get("namespace") != ns_serv:
                continue
            if template_labels(dep).get("app.kubernetes.io/name") == seletor.get("app.kubernetes.io/name"):
                alvo = (arquivo_dep, dep)
                break
        if alvo is None:
            a.append((arquivo, Achado(AVISO, "1.4", "nenhum Deployment no diretório com o app deste Service")))
            continue
        arquivo_dep, dep = alvo
        match_labels = ((dep.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}
        if seletor != match_labels:
            a.append((arquivo, Achado(FALHA, "1.4", f"selector do Service difere do matchLabels do Deployment ({arquivo_dep.name})")))
        labels_pod = template_labels(dep)
        for chave, valor in seletor.items():
            if labels_pod.get(chave) != valor:
                a.append((arquivo, Achado(FALHA, "1.4", f'selector "{chave}: {valor}" não casa com as labels do template do pod')))
        # 4.5 — targetPort tem que apontar para uma porta que o container de fato escuta
        portas_container: dict[int, str | None] = {}
        for cont in (((dep.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []:
            for porta in cont.get("ports") or []:
                if "containerPort" in porta:
                    portas_container[porta["containerPort"]] = porta.get("name")
        for porta_svc in spec.get("ports") or []:
            alvo_porta = porta_svc.get("targetPort", porta_svc.get("port"))
            if isinstance(alvo_porta, int) and alvo_porta not in portas_container:
                a.append((arquivo, Achado(FALHA, "4.5", f"targetPort {alvo_porta} não é porta que nenhum container escute")))
            if isinstance(alvo_porta, str) and alvo_porta not in portas_container.values():
                a.append((arquivo, Achado(FALHA, "4.5", f'targetPort "{alvo_porta}" não corresponde a nenhuma porta nomeada dos containers')))

    # 2.5 — PDB em prod (recomendado) e seletor do PDB casando com o pod
    if ambiente == "prod" and not pdbs:
        deployments_prod = [f for f, _ in deployments]
        for arquivo in deployments_prod:
            a.append((arquivo, Achado(AVISO, "2.5", "workload de prod sem PodDisruptionBudget")))
    for arquivo, pdb in pdbs:
        spec = pdb.get("spec") or {}
        minimo = spec.get("minAvailable")
        if ambiente == "prod" and (minimo is None or minimo < 1):
            a.append((arquivo, Achado(FALHA, "2.5", f"PDB com minAvailable {minimo} — mínimo 1 em prod")))
        seletor = (spec.get("selector") or {}).get("matchLabels") or {}
        ns_pdb = (pdb.get("metadata") or {}).get("namespace")
        alvo = None
        for _, dep in deployments:
            if (dep.get("metadata") or {}).get("namespace") != ns_pdb:
                continue
            if template_labels(dep).get("app.kubernetes.io/name") == seletor.get("app.kubernetes.io/name"):
                alvo = dep
                break
        if alvo is not None:
            labels_pod = template_labels(alvo)
            for chave, valor in seletor.items():
                if labels_pod.get(chave) != valor:
                    a.append((arquivo, Achado(FALHA, "1.4", f'selector do PDB "{chave}: {valor}" não casa com as labels do template do pod')))
    return a


def carregar_docs(diretorio: Path):
    """Lê todos os YAML do diretório. Retorna ([(arquivo, doc)], [(arquivo, erro)])."""
    pares: list[tuple[Path, dict]] = []
    erros: list[tuple[Path, str]] = []
    for arquivo in sorted(diretorio.rglob("*.y*ml")):
        try:
            for doc in yaml.safe_load_all(arquivo.read_text(encoding="utf-8")):
                if isinstance(doc, dict):
                    pares.append((arquivo, doc))
        except yaml.YAMLError as exc:
            erros.append((arquivo, str(exc)))
    return pares, erros


def main() -> int:
    raiz = Path(sys.argv[1] if len(sys.argv) > 1 else "manifests")
    if not raiz.exists():
        print("Nenhum manifesto encontrado — nada a validar.")
        return 0
    pares, erros = carregar_docs(raiz)
    if not pares and not erros:
        print("Nenhum manifesto encontrado — nada a validar.")
        return 0

    total_falhas = 0
    total_avisos = 0
    arquivos = sorted({f for f, _ in pares} | {f for f, _ in erros})

    for arquivo in arquivos:
        ambiente = arquivo.parent.name if arquivo.parent.name in AMBIENTES else None
        do_arquivo: list[tuple[Path, Achado]] = []
        if any(f == arquivo for f, _ in erros):
            msg = next(m for f, m in erros if f == arquivo)
            do_arquivo.append((arquivo, Achado(FALHA, "yaml", f"erro de parse: {msg.splitlines()[0]}")))
        docs_do_arquivo = [d for f, d in pares if f == arquivo]
        if arquivo in [f for f, _ in erros]:
            msg = next(m for f, m in erros if f == arquivo)
            do_arquivo.append((arquivo, Achado(FALHA, "yaml", f"erro de parse: {msg.splitlines()[0]}")))
        for doc in docs_do_arquivo:
            for achado in validar_objeto(doc, ambiente):
                do_arquivo.append((arquivo, achado))
        for caminho, achado in cruzar_diretorio([(f, d) for f, d in pares if f.parent == arquivo.parent], ambiente):
            if caminho == arquivo:
                do_arquivo.append((caminho, achado))

        falhas = [x for x in do_arquivo if x[1].nivel == FALHA]
        avisos = [x for x in do_arquivo if x[1].nivel == AVISO]
        total_falhas += len(falhas)
        total_avisos += len(avisos)
        relativo = arquivo.relative_to(raiz)
        if falhas:
            print(f"✗ {relativo}")
            for _, achado in falhas:
                print(f"    FALHA [{achado.regra}] {achado.msg}")
            for _, achado in avisos:
                print(f"    aviso [{achado.regra}] {achado.msg}")
        elif avisos:
            print(f"⚠ {relativo}")
            for _, achado in avisos:
                print(f"    aviso [{achado.regra}] {achado.msg}")
        else:
            print(f"✓ {relativo}")

    print()
    print(f"Regras da casa: {len(arquivos)} arquivo(s) · {total_falhas} falha(s) · {total_avisos} aviso(s)")
    if total_falhas:
        print("REVISAÇÃO BARRADA — regra obrigatória/proibida violada (nível FALHA).")
        return 1
    if total_avisos:
        print("APROVADO COM AVISOS — exceções a regras recomendadas precisam de justificativa no PR.")
    else:
        print("APROVADO — nenhuma violação das regras da casa.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
