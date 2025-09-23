import argparse, random
from pathlib import Path
from diagrams import Diagram, Cluster, Edge

# ------------------------
# AWS
# ------------------------
from diagrams.aws.compute import EC2, ECS, EKS, Lambda
from diagrams.aws.network import ELB, Route53, APIGateway
from diagrams.aws.database import RDS, Dynamodb
from diagrams.aws.storage import S3

# ------------------------
# AZURE
# ------------------------
from diagrams.azure.compute import VM, AKS
from diagrams.azure.network import (
    DNSPrivateZones as AzureDNS,
    LoadBalancers,
    ApplicationGateway,
)
from diagrams.azure.database import SQLDatabases, CosmosDb
from diagrams.azure.storage import BlobStorage

# --- Catálogo só com AWS e AZURE ---
PROVIDERS = {
    "aws": [Route53, ELB, APIGateway, EC2, ECS, EKS, Lambda, S3, RDS, Dynamodb],
    "azure": [
        AzureDNS,
        LoadBalancers,
        ApplicationGateway,
        VM,
        AKS,
        BlobStorage,
        SQLDatabases,
        CosmosDb,
    ],
}

DIRECTIONS = ["TB", "LR"]  # top-bottom ou left-right


def make_nodes(pool, count):
    """Cria lista de instâncias de nós a partir de classes aleatórias."""
    nodes = []
    for _ in range(count):
        cls = random.choice(pool)
        label = cls.__name__.lower()
        nodes.append(cls(label))
    return nodes


def wire(nodes):
    """Conecta nós em padrões simples aleatórios."""
    if len(nodes) < 2:
        return
    pattern = random.choice(["chain", "fanout", "pairings", "mixed"])
    if pattern == "chain":
        for i in range(len(nodes) - 1):
            nodes[i] >> nodes[i + 1]
    elif pattern == "fanout":
        root = nodes[0]
        for n in nodes[1:]:
            root >> n
    elif pattern == "pairings":
        for i in range(0, len(nodes) - 1, 2):
            nodes[i] - nodes[i + 1]
    else:  # mixed
        for i in range(len(nodes) - 1):
            op = random.choice([">>", "<<", "-"])
            if op == ">>":
                nodes[i] >> nodes[i + 1]
            elif op == "<<":
                nodes[i] << nodes[i + 1]
            else:
                nodes[i] - nodes[i + 1]


def build_one(idx: int, outdir: Path, fmt: str):
    # escolhe 1 ou 2 provedores (apenas aws/azure)
    chosen_keys = random.sample(["aws", "azure"], k=random.randint(1, 2))
    pool = []
    for k in chosen_keys:
        pool.extend(PROVIDERS[k])

    direction = random.choice(DIRECTIONS)
    filename = f"diagram_{idx:04d}"

    with Diagram(
        name=f"Auto Diagram {idx}",
        filename=str(outdir / filename),
        show=False,
        direction=direction,
        outformat=fmt,
    ):
        # candidatos de borda de entrada (DNS/LB/GW) só de AWS/Azure
        entry_candidates = [
            c
            for c in [
                Route53,
                AzureDNS,
                ELB,
                ApplicationGateway,
                LoadBalancers,
                APIGateway,
            ]
            if c in pool
        ]
        entry_cls = (
            random.choice(entry_candidates) if entry_candidates else random.choice(pool)
        )
        entry = entry_cls("entry")

        # cluster de serviços
        with Cluster("Services"):
            svc_nodes = make_nodes(pool, random.randint(2, 5))

        # cluster de dados
        with Cluster("Data"):
            data_nodes = make_nodes(pool, random.randint(1, 3))

        # cluster “observability” (opcional) – aqui usamos serviços genéricos dos pools
        obs_nodes = []
        if random.random() < 0.6:
            with Cluster("Observability"):
                obs_nodes = make_nodes(pool, random.randint(1, 3))

        # entry -> services
        for sn in svc_nodes:
            entry >> sn

        # services entre si
        wire(svc_nodes)

        # services -> data
        for sn in svc_nodes:
            dn = random.choice(data_nodes)
            style = random.choice([None, "dashed", "bold", "dotted"])
            if style:
                sn >> Edge(style=style) >> dn
            else:
                sn >> dn

        # observability conectado em “T”
        for on in obs_nodes:
            target = random.choice(svc_nodes + data_nodes)
            if random.random() < 0.4:
                on << Edge(label="collect") << target
            else:
                target >> on


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=50, help="quantidade de diagramas")
    ap.add_argument("--out", type=str, default="diagramas", help="pasta de saída")
    ap.add_argument(
        "--fmt",
        type=str,
        default="png",
        choices=["png", "svg", "jpg"],
        help="formato de saída",
    )
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    for i in range(1, args.n + 1):
        build_one(i, outdir, args.fmt)

    print(f"[OK] Gerados {args.n} diagramas em {outdir.resolve()}")


if __name__ == "__main__":
    main()
