"""Testes do validador das regras da casa (camada 1 do pipeline).

Fixture central: um Deployment válido de verdade. Cada teste injeta UMA
violação e afirma que o validador aponta a regra certa e barra (exit 1).
O teste "valido" garante que a base não gera nem falha nem aviso.
"""

import subprocess
import sys
from pathlib import Path

import yaml

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validar-regras-casa.py"


def rodar(tmp_path, docs, ambiente="dev"):
    """Grava os docs num diretório de ambiente e roda o validador via CLI."""
    diretorio = tmp_path / ambiente
    diretorio.mkdir()
    for i, doc in enumerate(docs):
        (diretorio / f"obj{i:02d}.yaml").write_text(
            yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
        )
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(diretorio)],
        capture_output=True,
        text=True,
    )


def rotulos(ns="nyx-dev"):
    return {
        "app.kubernetes.io/name": "nyx-api",
        "app.kubernetes.io/instance": ns,
        "app.kubernetes.io/part-of": "nyx",
        "app.kubernetes.io/managed-by": "platform",
    }


def base_container():
    return {
        "name": "api",
        "image": "registry.metacortex.io/nyx/api:2.9.1",
        "ports": [{"name": "http", "containerPort": 8080}],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "500m", "memory": "512Mi"},
        },
        "readinessProbe": {"httpGet": {"path": "/readyz", "port": 8080}},
        "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
        "env": [
            {
                "name": "APP_ENV",
                "valueFrom": {"configMapKeyRef": {"name": "nyx-api", "key": "app_env"}},
            }
        ],
    }


def base_deployment(ns="nyx-dev", replicas=1):
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "nyx-api",
            "namespace": ns,
            "labels": rotulos(ns),
            "annotations": {"metacortex.io/owner": "plataforma-nyx"},
        },
        "spec": {
            "replicas": replicas,
            "selector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "nyx-api",
                    "app.kubernetes.io/instance": ns,
                }
            },
            "template": {
                "metadata": {"labels": rotulos(ns)},
                "spec": {
                    "serviceAccountName": "nyx-api",
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 40,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
                    "containers": [base_container()],
                },
            },
        },
    }


def base_service(ns="nyx-dev"):
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "nyx-api",
            "namespace": ns,
            "labels": rotulos(ns),
            "annotations": {"metacortex.io/owner": "plataforma-nyx"},
        },
        "spec": {
            "type": "ClusterIP",
            "selector": {
                "app.kubernetes.io/name": "nyx-api",
                "app.kubernetes.io/instance": ns,
            },
            "ports": [{"name": "http", "port": 80, "targetPort": 8080}],
        },
    }


# --- o caminho feliz -------------------------------------------------------


def test_manifest_valido_passa_sem_falhas_nem_avisos(tmp_path):
    r = rodar(tmp_path, [base_deployment(), base_service()])
    assert r.returncode == 0, r.stdout
    assert "APROVADO — nenhuma violação" in r.stdout


# --- uma violação por teste, regra por regra -------------------------------


def test_nome_fora_de_kebab_case_barra_1_1(tmp_path):
    doc = base_deployment()
    doc["metadata"]["name"] = "NyxAPI"
    r = rodar(tmp_path, [doc])
    assert r.returncode == 1
    assert "FALHA [1.1]" in r.stdout


def test_rotulos_obrigatorios_ausentes_barra_1_3(tmp_path):
    doc = base_deployment()
    del doc["metadata"]["labels"]["app.kubernetes.io/part-of"]
    r = rodar(tmp_path, [doc])
    assert r.returncode == 1
    assert "FALHA [1.3]" in r.stdout


def test_seletor_do_service_nao_casa_barra_1_4(tmp_path):
    serv = base_service()
    # mesmo app, mas instance diferente do Deployment: selector != matchLabels
    serv["spec"]["selector"]["app.kubernetes.io/instance"] = "nyx-stg"
    r = rodar(tmp_path, [base_deployment(), serv])
    assert r.returncode == 1
    assert "FALHA [1.4]" in r.stdout


def test_tag_latest_proibida_barra_3_1(tmp_path):
    doc = base_deployment()
    doc["spec"]["template"]["spec"]["containers"][0]["image"] = (
        "registry.metacortex.io/nyx/api:latest"
    )
    r = rodar(tmp_path, [doc])
    assert r.returncode == 1
    assert "FALHA [3.1]" in r.stdout


def test_registry_externo_barra_3_7(tmp_path):
    doc = base_deployment()
    doc["spec"]["template"]["spec"]["containers"][0]["image"] = (
        "docker.io/nyx/api:2.9.1"
    )
    r = rodar(tmp_path, [doc])
    assert r.returncode == 1
    assert "FALHA [3.7]" in r.stdout


def test_segredo_em_texto_puro_barra_3_3(tmp_path):
    doc = base_deployment()
    doc["spec"]["template"]["spec"]["containers"][0]["env"].append(
        {
            "name": "DATABASE_URL",
            "value": "postgres://nyx:s3nh4@pg.nyx-dev.svc:5432/nyx",
        }
    )
    r = rodar(tmp_path, [doc])
    assert r.returncode == 1
    assert "FALHA [3.3]" in r.stdout


def test_targetport_orfao_barra_4_5(tmp_path):
    serv = base_service()
    serv["spec"]["ports"][0]["targetPort"] = 9999
    r = rodar(tmp_path, [base_deployment(), serv])
    assert r.returncode == 1
    assert "FALHA [4.5]" in r.stdout


def test_probe_em_porta_nao_exposta_barra_2_2(tmp_path):
    doc = base_deployment()
    doc["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"][
        "port"
    ] = 9999
    r = rodar(tmp_path, [doc])
    assert r.returncode == 1
    assert "FALHA [2.2]" in r.stdout
    assert "não expõe" in r.stdout


def test_prod_com_uma_replica_barra_2_3(tmp_path):
    doc = base_deployment(ns="nyx-prod", replicas=1)
    doc["spec"]["strategy"] = {
        "type": "RollingUpdate",
        "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
    }
    r = rodar(tmp_path, [doc], ambiente="prod")
    assert r.returncode == 1
    assert "FALHA [2.3]" in r.stdout


def test_prod_sem_pdb_da_aviso_2_5(tmp_path):
    doc = base_deployment(ns="nyx-prod", replicas=2)
    doc["spec"]["strategy"] = {
        "type": "RollingUpdate",
        "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
    }
    r = rodar(tmp_path, [doc], ambiente="prod")
    assert r.returncode == 0, r.stdout
    assert "aviso [2.5]" in r.stdout


def test_yaml_quebrado_barra_no_parse(tmp_path):
    diretorio = tmp_path / "dev"
    diretorio.mkdir()
    (diretorio / "quebrado.yaml").write_text("metadata: [unclosed", encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(SCRIPT), str(diretorio)],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 1
    assert "erro de parse" in r.stdout
