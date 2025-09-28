# -*- coding: utf-8 -*-
# ============================================================
# Analisador STRIDE para Diagramas - app.py (comentado)
# ------------------------------------------------------------
# • Flask para interface web
# • YOLO (Ultralytics) para detecção de componentes no diagrama
# • Gemini / OpenAI (opcional) para gerar análise STRIDE e mitigações
# • ReportLab para gerar PDF A4 estruturado
# • PIL para anotações visuais (bounding boxes e legenda)
# ============================================================

from __future__ import annotations
import os
import time
import traceback
from datetime import datetime
from typing import List, Dict, Tuple

# -----------------------------
# Flask (servidor web e rotas)
# -----------------------------
from flask import (
    Flask,
    request,
    render_template_string,
    redirect,
    url_for,
    send_from_directory,
    flash,
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Carrega variáveis do arquivo .env (chaves, flags e parâmetros)
load_dotenv()

# -----------------------------
# Imagens e PDF
# -----------------------------
from PIL import Image, ImageDraw, ImageFont

try:
    # ReportLab → geração de PDF (A4, estilos, componentes de layout)
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, PageBreak, Spacer, Image as RLImage,
        ListFlowable, ListItem
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
except Exception as e:
    # Se ReportLab não estiver instalado, encerramos com mensagem clara
    raise SystemExit(f"Erro ao importar ReportLab: {e}")

# -----------------------------
# Torch (opcional) → checa GPU
# -----------------------------
try:
    import torch
    _HAS_CUDA = torch.cuda.is_available()
    if _HAS_CUDA:
        # Ativa autotuning do cuDNN para melhorar performance em imagens repetitivas
        torch.backends.cudnn.benchmark = True
except Exception:
    _HAS_CUDA = False

# ============================================================
# Configurações globais (muitas vindas do .env)
# ============================================================

# Limite de upload (MB) para arquivos enviados via formulário
MAX_CONTENT_LENGTH_MB = int(os.getenv("MAX_CONTENT_LENGTH_MB", "15"))

# Extensões aceitas para upload (diagramas e logo)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

# Pastas básicas do projeto
STATIC_FOLDER  = os.path.abspath("static")
UPLOAD_FOLDER  = os.path.abspath("uploads")
PREVIEW_FOLDER = os.path.abspath("previews")
OUTPUT_FOLDER  = os.path.abspath("outputs")
FONTS_FOLDER   = os.path.abspath("fonts")

# Parâmetros de desempenho e YOLO
FAST_IMG_MAX_SIDE = int(os.getenv("FAST_IMG_MAX_SIDE", "1280"))  # escala máx. do maior lado (acelera inferência)
YOLO_CONF         = float(os.getenv("YOLO_CONF", "0.30"))        # confiança mínima de detecção
YOLO_MAX_DET      = int(os.getenv("YOLO_MAX_DET", "50"))         # limite de detecções por imagem
MAX_COMPONENTS    = int(os.getenv("MAX_COMPONENTS", "25"))       # quantos componentes listar no PDF/UI
QUICK_DEFAULT     = os.getenv("QUICK_DEFAULT", "0") == "1"       # modo rápido padrão (usa placeholders, sem LLM)

# Flag geral para desabilitar uso de LLMs (útil em ambiente offline)
DISABLE_LLM = os.getenv("DISABLE_LLM", "0") == "1"

# Gemini (Google) – chave e modelo
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-flash-latest")

# OpenAI – chave e modelo (via LangChain ChatOpenAI)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL   = os.getenv("OPENAI_MODEL", "gpt-5-nano")

# Caminho para os pesos do YOLO (.pt)
YOLO_WEIGHTS = os.getenv("YOLO_WEIGHTS", os.path.join("weights", "treinamento_yolo_aws_best.pt"))

# IOU do NMS (quanto maior, mais caixas sobrepostas serão mantidas)
NMS_IOU = float(os.getenv("NMS_IOU", "0.5"))

# ============================================================
# Preparação de pastas e limpeza de prévias antigas
# ============================================================

# Garante que as pastas críticas existem
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PREVIEW_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Limpa imagens de preview com mais de 2 dias (higiene de disco)
_now = time.time()
for f in list(os.listdir(PREVIEW_FOLDER)):
    p = os.path.join(PREVIEW_FOLDER, f)
    try:
        if os.path.isfile(p) and _now - os.path.getmtime(p) > 2 * 24 * 3600:
            os.remove(p)
    except Exception:
        # Não interrompe o servidor se falhar na remoção
        pass

# ============================================================
# Flask – inicialização
# ============================================================

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH_MB * 1024 * 1024
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = os.getenv("APP_SECRET_KEY", "dev_secret_change_me")  # troque em produção

# Modelo YOLO é carregado sob demanda (primeira requisição)
_YOLO_MODEL = None

# ============================================================
# LLM: Gemini
# ============================================================

_gemini = None
if not DISABLE_LLM:
    try:
        import google.generativeai as genai
        if not GEMINI_API_KEY:
            print("[AVISO] GEMINI_API_KEY não definido. Use DISABLE_LLM=1 para pular LLM.")
            DISABLE_LLM = True
        else:
            genai.configure(api_key=GEMINI_API_KEY)
            _gemini = genai.GenerativeModel(GEMINI_MODEL)
    except Exception as e:
        # Se falhar, seguimos com placeholders
        print(f"[AVISO] Falha ao iniciar Gemini: {e}. Usando placeholders.")
        DISABLE_LLM = True
        _gemini = None

# ============================================================
# LLM: OpenAI (via LangChain)
# ============================================================

_openai = None
if not DISABLE_LLM:
    try:
        from langchain_openai import ChatOpenAI
        if not OPENAI_API_KEY:
            print("[AVISO] OPENAI_API_KEY não definido. Use DISABLE_LLM=1 para pular LLM.")
            DISABLE_LLM = True
        else:
            _openai = ChatOpenAI(model=OPENAI_MODEL, api_key=OPENAI_API_KEY)
    except Exception as e:
        print(f"[AVISO] Falha ao iniciar OpenAI: {e}. Usando placeholders.")
        DISABLE_LLM = True
        _openai = None

# ============================================================
# YOLO – carregamento único + warm-up
# ============================================================

def get_yolo():
    """
    Carrega o modelo YOLO uma única vez e realiza um warm-up leve para
    evitar o custo alto de primeira inferência. Erros de warm-up são ignorados.
    """
    global _YOLO_MODEL
    if _YOLO_MODEL is None:
        try:
            from ultralytics import YOLO
        except Exception as e:
            raise SystemExit(f"Ultralytics não instalado: {e}")

        if not os.path.exists(YOLO_WEIGHTS):
            raise FileNotFoundError(f"Pesos YOLO não encontrados: {YOLO_WEIGHTS}")

        _YOLO_MODEL = YOLO(YOLO_WEIGHTS)

        # Warm-up opcional com imagem dummy (imgsz pequeno, sem salvar)
        try:
            _YOLO_MODEL.predict(
                imgsz=min(FAST_IMG_MAX_SIDE, 640),
                conf=0.10,
                max_det=1,
                verbose=False,
                device=0 if _HAS_CUDA else "cpu",
                half=_HAS_CUDA,
            )
        except Exception:
            pass
    return _YOLO_MODEL

# ============================================================
# Mapeamento de labels → nomes legíveis (apresentação)
# ============================================================

service_map: Dict[str, str] = {
    "AWS-Backup": "AWS Backup",
    "AWS-Category_Compute": "Serviço de Computação AWS (EC2/Fargate)",
    "AWS-Cloud-logo": "Logo da AWS Cloud",
    "AWS-CloudFront": "Amazon CloudFront",
    "AWS-CloudTrail": "AWS CloudTrail",
    "AWS-CloudWatch": "Amazon CloudWatch",
    "AWS-EFS": "Amazon Elastic File System (EFS)",
    "AWS-ElastiCache": "Amazon ElastiCache",
    "AWS-Key-Management-Service": "AWS Key Management Service (KMS)",
    "AWS-Private-subnet": "Sub-rede Privada da AWS",
    "AWS-Private_vpc": "VPC Privada da AWS",
    "AWS-Public-subnet": "Sub-rede Pública da AWS",
    "AWS-RDS": "Amazon RDS",
    "AWS-Region": "Região da AWS",
    "AWS-Res_Elastic-Load-Balancing_Application-Load-Balancer": "Application Load Balancer (ALB)",
    "AWS-Res_Users": "Usuários da AWS",
    "AWS-Scaling-group": "Grupo de Auto Scaling da AWS",
    "AWS-Shield": "AWS Shield",
    "AWS-Simple-Email-Service": "Amazon SES",
    "AWS-WAF": "AWS WAF",
    "Azure_api": "API do Azure",
    "Azure_api_gateway": "Azure API Gateway",
    "Azure_cloud_services": "Azure Cloud Services",
    "Azure_http": "Protocolo HTTP no Azure",
    "Azure_integration-204-Logic-Apps": "Azure Logic Apps",
    "Azure_management-portal": "Portal de Gerenciamento do Azure",
    "Azure_microsoft_entra": "Microsoft Entra ID (Azure AD)",
    "Azure_resource_group": "Grupo de Recursos do Azure",
    "Azure_services": "Serviços do Azure",
    "Azure_users": "Usuários do Azure",
}

# ============================================================
# Helpers de arquivo e imagem
# ============================================================

def allowed_file(filename: str) -> bool:
    """Confere se a extensão do arquivo é suportada."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def load_font(size=18):
    """Tenta carregar uma fonte TrueType; caso falhe, usa fonte padrão do PIL."""
    try:
        return ImageFont.truetype(os.path.join(FONTS_FOLDER, "arial.ttf"), size)
    except Exception:
        try:
            return ImageFont.truetype("arial.ttf", size)
        except Exception:
            return ImageFont.load_default()

def _resize_if_large(path: str, max_side: int) -> str:
    """
    Reduz a imagem no próprio arquivo quando o maior lado excede max_side.
    Isso reduz o custo de inferência no YOLO sem alterar proporção.
    """
    try:
        im = Image.open(path).convert("RGB")
        w, h = im.size
        m = max(w, h)
        if m > max_side:
            scale = max_side / float(m)
            im = im.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
            im.save(path, optimize=True, quality=92)
    except Exception:
        pass
    return path

# ============================================================
# NMS por IoU (simples) para limpar caixas muito sobrepostas
# ============================================================

def iou(box1, box2):
    """Calcula Intersection-over-Union entre duas caixas [x1,y1,x2,y2]."""
    x_min_inter = max(box1[0], box2[0])
    y_min_inter = max(box1[1], box2[1])
    x_max_inter = min(box1[2], box2[2])
    y_max_inter = min(box1[3], box2[3])
    inter_w = max(0, x_max_inter - x_min_inter)
    inter_h = max(0, y_max_inter - y_min_inter)
    inter_area = inter_w * inter_h
    box1_area = (box1[2] - box1[0]) * (box1[3] - box1[1])
    box2_area = (box2[2] - box2[0]) * (box2[3] - box2[1])
    union_area = box1_area + box2_area - inter_area
    return 0 if union_area == 0 else inter_area / union_area

def nms_iou_filter(boxes, class_names_map, iou_threshold=0.5):
    """
    Aplica NMS (Non-Maximum Suppression) baseado em IoU:
    - Ordena por confiança descrescente.
    - Mantém a caixa se ela não tiver IoU alto com caixas já mantidas.
    - Anexa o nome de classe (legível) ao final.
    """
    if not hasattr(boxes, "tolist"):
        return []
    sorted_boxes = sorted(boxes.tolist(), key=lambda b: float(b[4]), reverse=True)
    kept = []
    for b in sorted_boxes:
        if any(iou(b[:4], kb[:4]) > iou_threshold for kb in kept):
            continue
        conf = float(b[4])
        cls_id = int(b[5])
        class_name = class_names_map.get(cls_id, str(cls_id))
        kept.append(b + [class_name])
    return kept

# ============================================================
# Anotação visual (desenha caixas e legenda) com PIL
# ============================================================

def annotate_image(original_path: str, detections: List, color_hex: str = "#0EA5E9"):
    """
    Desenha bounding boxes numeradas sobre a imagem e cria uma versão com legenda.
    Retorna: (caminho_img_sem_legenda, lista_de_linhas_de_legenda)
    """
    img = Image.open(original_path).convert("RGB")
    draw = ImageDraw.Draw(img)
    font = load_font(20)
    color = tuple(int(color_hex.strip("#")[i:i+2], 16) for i in (0, 2, 4))

    legend_lines = []
    iter_boxes = detections if MAX_COMPONENTS <= 0 else detections[:MAX_COMPONENTS]
    for i, b in enumerate(iter_boxes, start=1):
        x1, y1, x2, y2, conf, cls_id, class_name = b
        x1, y1, x2, y2 = map(int, [x1, y1, x2, y2])
        draw.rectangle([x1, y1, x2, y2], outline=color, width=3)
        draw.text((x1, max(0, y1 - 24)), str(i), fill=color, font=font)
        name = service_map.get(class_name, class_name)
        legend_lines.append(f"{i}: {name} ({conf:.2f})")

    # acrescenta uma tarja branca abaixo para exibir a legenda
    line_h = 26
    extra_h = len(legend_lines) * line_h + 18 if legend_lines else 0
    if extra_h > 0:
        w, h = img.size
        new_img = Image.new("RGB", (w, h + extra_h), (255, 255, 255))
        new_img.paste(img, (0, 0))
        draw2 = ImageDraw.Draw(new_img)
        y = h + 10
        for line in legend_lines:
            draw2.text((16, y), line, fill=(0, 0, 0), font=font)
            y += line_h
        # substitui a imagem que será salva com legenda
        img_with_legend = new_img
    else:
        img_with_legend = img.copy()

    base = os.path.basename(original_path)
    out_legend_path = os.path.join(PREVIEW_FOLDER, f"labeled_legend_{base}")
    img_with_legend.save(out_legend_path, optimize=True)

    out_path = os.path.join(PREVIEW_FOLDER, f"labeled_{base}")
    img.save(out_path, optimize=True)
    return out_path, legend_lines

# ============================================================
# Cache para evitar chamadas repetidas ao LLM por componente
# chave: "{LLM}_{component_name}" → valor: (analysis, mitigations)
# ============================================================

LLM_CACHE: Dict[str, Tuple[str, str]] = {}

# ============================================================
# Parsing de texto → seções STRIDE (organiza bullets por categoria)
# ============================================================

import re, unicodedata

_STRIDE_CANON = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]

# aliases PT/EN (para robustez com respostas do LLM)
_STRIDE_ALIASES = {
    "Spoofing": [
        r"spoofing", r"personifica(?:ç|c)[aã]o", r"impersona(?:ç|c)[aã]o",
        r"falsifica(?:ç|c)[aã]o\s+de\s+identidade",
    ],
    "Tampering": [
        r"tampering", r"manipula(?:ç|c)[aã]o", r"alter[aç][aã]o\s+n[aã]o\s+autorizada",
        r"adultera(?:ç|c)[aã]o",
    ],
    "Repudiation": [
        r"repudiation", r"rep(?:ú|u)d[ií]o", r"n[aã]o\s+rep[uú]dio",
        r"nega(?:ç|c)[aã]o\s+de\s+autoria",
    ],
    "Information Disclosure": [
        r"information\s+disclosure",
        r"divulga(?:ç|c)[aã]o\s+de\s+informa(?:ç|c)[oõ]es",
        r"exposi(?:ç|c)[aã]o\s+de\s+dados",
        r"vazamento\s+de\s+informa(?:ç|c)[oõ]es",
        r"info\s*disclosure",
    ],
    "Denial of Service": [
        r"denial\s+of\s+service", r"nega(?:ç|c)[aã]o\s+de\s+servi[cç]o",
        r"\bdo?s\b",
    ],
    "Elevation of Privilege": [
        r"elevation\s+of\s+privilege",
        r"eleva(?:ç|c)[aã]o\s+de\s+privil[eé]gio",
        r"\beop\b",
    ],
}

_ALIAS_RE = "|".join(rf"(?:{alias})"
                     for aliases in _STRIDE_ALIASES.values() for alias in aliases)

# Cabeçalho puro (apenas o nome da categoria) – tolera bullets e parênteses
_HEADER_PURE_RE = re.compile(
    rf"""^\s{{0,3}}(?:[-*#]+\s*)?
         (?P<hdr>{_ALIAS_RE})
         (?:\s*\([^)]*\))?
         \s*[:\-]?\s*$
    """,
    re.IGNORECASE | re.VERBOSE
)

# Cabeçalho inline do tipo "Categoria: texto..."
_HEADER_INLINE_RE = re.compile(
    rf"""^\s*(?P<hdr>{_ALIAS_RE})
         (?:\s*\([^)]*\))?\s*
         \s*[:\-]\s*
         (?P<rest>.+?)\s*$
    """,
    re.IGNORECASE | re.VERBOSE
)

def _normalize_text(s: str) -> str:
    """Normaliza unicode e remove marcadores/ênfases comuns."""
    s = unicodedata.normalize("NFKC", s or "")
    s = s.replace("•", "*").replace("–", "-").replace("—", "-")
    s = s.replace("**", "").replace("__", "")
    return s.strip()

def _canonicalize(header: str) -> str:
    """Converte alias para a forma canônica da categoria."""
    h = _normalize_text(header).lower()
    for canon, aliases in _STRIDE_ALIASES.items():
        for a in aliases:
            if re.fullmatch(a, h, flags=re.IGNORECASE):
                return canon
    for canon in _STRIDE_CANON:
        if canon.lower() == h:
            return canon
    return header.strip().title()

# Palavras-chave para buckets automáticos quando o LLM não separa por categoria
_AUTO_BUCKET = {
    "Spoofing": [r"\bmfa\b", r"identidade", r"impersona", r"phish"],
    "Tampering": [r"inje(c|ç)[aã]o", r"\balter", r"manipula", r"modifica", r"\biac\b", r"policy"],
    "Repudiation": [r"auditoria", r"\blogs?\b", r"repud"],
    "Information Disclosure": [r"criptograf", r"vazam", r"expos", r"\bpii\b", r"token", r"credenciais"],
    "Denial of Service": [r"\bdo?s\b", r"\bnega", r"exaust", r"indispon", r"\brate\b", r"\bquota"],
    "Elevation of Privilege": [r"privil", r"eleva", r"\beop\b", r"\brbac\b", r"assumir"],
}

def _guess_category(text: str) -> str | None:
    """Heurística simples para classificar um bullet não categorizado."""
    t = _normalize_text(text).lower()
    best, score = None, 0
    for cat, pats in _AUTO_BUCKET.items():
        sc = sum(1 for p in pats if re.search(p, t))
        if sc > score:
            best, score = cat, sc
    return best

def parse_stride_sections(text: str) -> dict[str, list[str]]:
    """
    Converte um texto genérico do LLM em um dicionário:
      { "Spoofing": [...], "Tampering": [...], ... }
    Aceita cabeçalhos puros, inline e bullets soltos.
    """
    sections = {k: [] for k in _STRIDE_CANON}
    if not text:
        return sections

    current = None
    for raw in text.splitlines():
        line = _normalize_text(raw)
        if not line:
            continue

        # 1) Cabeçalho inline
        m = _HEADER_INLINE_RE.match(line)
        if m:
            current = _canonicalize(m.group("hdr"))
            first = m.group("rest").strip(" -:;")
            if first:
                sections[current].append(first)
            continue

        # 2) Cabeçalho puro
        m = _HEADER_PURE_RE.match(line)
        if m:
            current = _canonicalize(m.group("hdr"))
            continue

        # 3) Bullet
        m = re.match(r"^(\*|-|\d+[\.\)])\s+(.*)$", line)
        if m:
            item = m.group(2).strip()

            # 3a) bullet que é cabeçalho inline
            mi = _HEADER_INLINE_RE.match(item)
            if mi:
                current = _canonicalize(mi.group("hdr"))
                rest = mi.group("rest").strip(" -:;")
                if rest:
                    sections[current].append(rest)
                continue

            # 3b) bullet que é cabeçalho puro
            mp = _HEADER_PURE_RE.match(item)
            if mp:
                current = _canonicalize(mp.group("hdr"))
                continue

            # 3c) bullet normal (coloca no bucket atual ou tenta adivinhar)
            if current:
                sections[current].append(item)
            else:
                cat = _guess_category(item) or "Tampering"
                sections[cat].append(item)
            continue

        # 4) Linha solta (sem bullet) → cai no bucket atual ou heurística
        if current:
            sections[current].append(line)
        else:
            cat = _guess_category(line) or "Tampering"
            sections[cat].append(line)

    return sections

def _sanitize_para(s: str) -> str:
    """Escapa HTML básico e mantém <b> pseudo-markdown."""
    if not s:
        return ""
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>")
    return s

def sections_to_html(secs: dict[str, list[str]]) -> dict[str, list[str]]:
    """Aplica _sanitize_para em todos os itens para exibição segura na UI."""
    return {k: [_sanitize_para(v) for v in (secs.get(k) or [])] for k in _STRIDE_CANON}

# Substituições comuns EN→PT para melhorar consistência do texto do LLM
_PT_REPLACEMENTS = [
    (r"\bLeast Privilege\b", "menor privilégio"),
    (r"\bPrinciple of Least Privilege\b", "princípio do menor privilégio"),
    (r"\bRole-?Based Access Control\b", "controle de acesso baseado em função (RBAC)"),
    (r"\bJust-?In-?Time\b", "just-in-time"),
    (r"\bRate Limiting\b", "limitação de taxa"),
    (r"\bThrottling\b", "limitação de taxa"),
    (r"\bDenial of Wallet\b", "negação de carteira (custos)"),
    (r"\bBlueprints?\b", "Blueprints"),
    (r"\bResource Locks?\b", "bloqueios de recursos"),
    (r"\bWrite-Once-Read-Many\b", "grava-uma-vez/lê-muitas (WORM)"),
    (r"\bKey Vault\b", "Key Vault"),
    (r"\bService Principals?\b", "Service Principal"),
    (r"\bManaged Identities?\b", "Identidade Gerenciada"),
    (r"\bWeb Application Firewall\b", "WAF (Firewall de Aplicação Web)"),
    (r"\bCertificate Pinning\b", "fixação de certificado"),
    (r"\bProof[- ]of[- ]Possession\b", "prova de posse (PoP)"),
    (r"\bHSTS\b", "HSTS"),
    (r"\bTLS\b", "TLS"),
    (r"\bHTTP Strict Transport Security\b", "HSTS (política de transporte estrito)"),
    (r"\bAudit (?:Logs?|Logging)\b", "logs de auditoria"),
    (r"\bSIEM\b", "SIEM"),
    (r"\bDDoS\b", "DDoS"),
    (r"\bJWTs?\b", "JWT"),
    (r"\bensure\b", "garantir"),
    (r"\benforce\b", "impor"),
    (r"\brequire\b", "exigir"),
    (r"\bconfigure\b", "configurar"),
    (r"\benable\b", "habilitar"),
    (r"\bdisable\b", "desabilitar"),
    (r"\bmonitor\b", "monitorar"),
    (r"\bsecrets?\b", "segredos"),
    (r"\bbackends?\b", "backend"),
]

_SINGLE_LETTER_HDR = re.compile(
    r"""^\s*
        (?:[-*•#]\s*)?
        ([sstrideSSTRIDE])
        \s*(?:[-–—:])?\s*$
    """, re.VERBOSE
)

_CAT_LINE = re.compile(
    r"""^\s*([STIRDE])\s*[-–—]?\s*
        (Spoofing|Tampering|Repudiation|Information\s+Disclosure|Denial\s+of\s+Service|Elevation\s+of\s+Privilege)\s*$
    """, re.IGNORECASE | re.VERBOSE
)

def strip_stride_artifacts(text: str) -> str:
    """Remove linhas 'S/T/R/I/D/E' e cabeçalhos soltos que às vezes o LLM injeta."""
    if not text:
        return text
    out_lines = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if _SINGLE_LETTER_HDR.match(line):
            continue
        if _CAT_LINE.match(line):
            continue
        out_lines.append(raw)
    return "\n".join(out_lines)

def ensure_ptbr(text: str) -> str:
    """Tradução leve de termos frequentes para PT-BR sem mexer nas siglas úteis."""
    if not text:
        return text
    out = text
    for pat, repl in _PT_REPLACEMENTS:
        out = re.sub(pat, repl, out, flags=re.IGNORECASE)
    # Normaliza nomes de categorias se vierem em EN dentro do corpo
    out = re.sub(r"\bInformation Disclosure\b", "Divulgação de Informação", out, flags=re.IGNORECASE)
    out = re.sub(r"\bElevation of Privilege\b", "Elevação de Privilégio", out, flags=re.IGNORECASE)
    out = re.sub(r"\bDenial of Service\b", "Negação de Serviço", out, flags=re.IGNORECASE)
    out = re.sub(r"\bRepudiation\b", "Repúdio", out, flags=re.IGNORECASE)
    out = re.sub(r"\bTampering\b", "Violação de Integridade (Tampering)", out, flags=re.IGNORECASE)
    out = re.sub(r"\bSpoofing\b", "Representação (Spoofing)", out, flags=re.IGNORECASE)
    # Remove linhas como "S - Spoofing" quando aparecem no corpo
    out = re.sub(
        r"^\s*[STIRDE]\s*-\s*(Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege)\s*$",
        "", out, flags=re.IGNORECASE | re.MULTILINE
    )
    return out

# ============================================================
# Chamadas de LLM (Gemini / OpenAI) com cache
# ============================================================

def call_gemini_stride(llm: str, component_name: str) -> Tuple[str, str]:
    """
    Retorna (análise, mitigações) via Gemini para um componente específico.
    - Se LLM estiver desabilitado, retorna placeholders.
    - Força PT-BR e estrutura em bullets, sem cabeçalhos extras.
    """
    key = f"{llm}_{component_name}"
    if key in LLM_CACHE:
        return LLM_CACHE[key]

    if DISABLE_LLM or _gemini is None:
        # Placeholders curtos para uso quando LLM está desligado
        analysis = (
            "Spoofing: riscos de representação de identidades.\n"
            "Tampering: alterações não autorizadas em configurações e dados.\n"
            "Repudiation: falta de trilhas de auditoria imutáveis.\n"
            "Information Disclosure: exposição indevida de informações e segredos.\n"
            "Denial of Service: indisponibilidade por exaustão ou DDoS.\n"
            "Elevation of Privilege: abuso ou escalonamento de permissões."
        )
        mitig = (
            "Spoofing: MFA e autenticação forte entre serviços.\n"
            "Tampering: políticas, assinatura de artefatos e versionamento.\n"
            "Repudiation: logs imutáveis e retenção centralizada.\n"
            "Information Disclosure: criptografia, Key Vault e mínimos privilégios de leitura.\n"
            "Denial of Service: limitação de taxa e proteção DDoS.\n"
            "Elevation of Privilege: RBAC com menor privilégio e PIM/JIT."
        )
        return analysis, mitig

    # Regras para moldar o estilo da resposta
    base_rules = (
        "Responda EXCLUSIVAMENTE em português do Brasil (pt-BR). "
        "Não use palavras em inglês; quando precisar citar uma sigla (ex.: RBAC, DDoS, TLS), mantenha a sigla e explique em português. "
        "Formate como listas por categoria STRIDE, sem introduções extras, sem conclusões e sem repetir as categorias dentro dos itens. "
        "Não escreva cabeçalhos além das categorias STRIDE. Seja específico para Azure."
    )

    # Prompt para ameaças
    prompt_a = f"""
    {base_rules}
    Analise o componente de arquitetura "{component_name}" usando STRIDE.
    Para cada categoria, produza 3–6 bullets objetivos.
    """

    try:
        resp_a = _gemini.generate_content(prompt_a)
        analysis = resp_a.text or ""
    except Exception as e:
        analysis = f"[Erro ao obter análise do Gemini: {e}]"

    # Prompt para mitigações
    prompt_m = f"""
    {base_rules}
    Com base nas ameaças a seguir, liste MITIGAÇÕES práticas (1 linha por bullet) por categoria STRIDE, 3–6 bullets cada:
    ---
    {analysis}
    ---
    """

    try:
        resp_m = _gemini.generate_content(prompt_m)
        mitig = resp_m.text or ""
    except Exception as e:
        mitig = f"[Erro ao obter mitigações do Gemini: {e}]"

    # Normalizações para PT-BR e remoção de artefatos
    analysis = ensure_ptbr(analysis)
    mitig   = ensure_ptbr(mitig)

    # Grava em cache
    LLM_CACHE[key] = (analysis, mitig)
    return analysis, mitig


def call_openai_stride(llm: str, component_name: str) -> Tuple[str, str]:
    """
    Retorna (análise, mitigações) via OpenAI (LangChain ChatOpenAI).
    - Força PT-BR
    - Remove artefatos 'S - Spoofing', etc.
    """
    key = f"{llm}_{component_name}"
    if key in LLM_CACHE:
        return LLM_CACHE[key]

    if DISABLE_LLM or _openai is None:
        # Placeholders quando LLM está desligado
        analysis = (
            "Spoofing: riscos de representação de identidades.\n"
            "Tampering: alterações não autorizadas em configurações e dados.\n"
            "Repudiation: falta de trilhas de auditoria imutáveis.\n"
            "Information Disclosure: exposição indevida de informações e segredos.\n"
            "Denial of Service: indisponibilidade por exaustão ou DDoS.\n"
            "Elevation of Privilege: abuso ou escalonamento de permissões."
        )
        mitig = (
            "Spoofing: MFA e autenticação forte entre serviços.\n"
            "Tampering: políticas, assinatura de artefatos e versionamento.\n"
            "Repudiation: logs imutáveis e retenção centralizada.\n"
            "Information Disclosure: criptografia, Key Vault e mínimos privilégios de leitura.\n"
            "Denial of Service: limitação de taxa e proteção DDoS.\n"
            "Elevation of Privilege: RBAC com menor privilégio e PIM/JIT."
        )
        return analysis, mitig

    base_rules = (
        "Responda EXCLUSIVAMENTE em português do Brasil (pt-BR). "
        "NÃO escreva introdução nem conclusão. "
        "NÃO repita o nome da categoria dentro dos bullets. "
        "NÃO use cabeçalhos de uma única letra (S, T, R, I, D, E) nem linhas como 'S - Spoofing'. "
        "Formato OBRIGATÓRIO: blocos por categoria STRIDE, cada um contendo de 3 a 6 bullets curtos."
    )

    # Prompt para ameaças
    prompt_a = f"""
    {base_rules}
    Analise o componente de arquitetura "{component_name}" usando STRIDE (Spoofing, Tampering, Repudiation,
    Information Disclosure, Denial of Service, Elevation of Privilege). Seja específico para Azure.
    Produza SOMENTE os bullets das categorias (sem outros títulos). 
    """

    try:
        resp_a = _openai.invoke(prompt_a)
        analysis = getattr(resp_a, "content", "") or ""
    except Exception as e:
        analysis = f"[Erro ao obter análise do OpenAI: {e}]"

    # Prompt para mitigações
    prompt_m = f"""
    {base_rules}
    Agora, com base nas ameaças acima, gere MITIGAÇÕES PRÁTICAS para cada categoria STRIDE (3 a 6 bullets cada).
    Apenas bullets, sem cabeçalhos extra. Seja objetivo e use terminologia do Azure.
    ---
    {analysis}
    ---
    """

    try:
        resp_m = _openai.invoke(prompt_m)
        mitig = getattr(resp_m, "content", "") or ""
    except Exception as e:
        mitig = f"[Erro ao obter mitigações do OpenAI: {e}]"

    # Pós-processamento
    analysis = ensure_ptbr(strip_stride_artifacts(analysis))
    mitig   = ensure_ptbr(strip_stride_artifacts(mitig))

    LLM_CACHE[key] = (analysis, mitig)
    return analysis, mitig

# ============================================================
# Geração de PDF (A4) com cabeçalho, imagens e listas
# ============================================================

def build_pdf_a4(
    pdf_path: str,
    title: str,
    subtitle: str,
    brand_color: str,
    logo_path: str | None,
    source_image_path: str,
    labeled_image_path: str,
    legend: List[str],
    llm: str,
    per_component: List[Tuple[str, str, str]],
):
    """
    Monta o PDF final com:
      • Cabeçalho (cor da marca + logo + timestamp)
      • Figura 1: diagrama original
      • Figura 2: diagrama anotado + legenda
      • Seções por componente (Análise STRIDE + Mitigações)
    """
    W, H = A4
    try:
        primary = HexColor(brand_color)
    except Exception:
        primary = HexColor("#7C3AED")

    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "Body", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=13, alignment=TA_LEFT
    )
    h_comp = ParagraphStyle(
        "Comp", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=14, textColor=primary, spaceBefore=8, spaceAfter=6
    )
    h_label = ParagraphStyle(
        "Label", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=10, spaceBefore=4, spaceAfter=2
    )

    def _header(canvas, doc):
        """Cabeçalho repetido em todas as páginas."""
        canvas.saveState()
        canvas.setFillColor(primary)
        canvas.rect(0, H - 70, W, 70, fill=True, stroke=False)
        if logo_path and os.path.exists(logo_path):
            try:
                canvas.drawImage(ImageReader(logo_path), 24, H - 60, 64, 48, preserveAspectRatio=True, mask='auto')
            except Exception:
                pass
        canvas.setFillColor("white")
        canvas.setFont("Helvetica-Bold", 18)
        canvas.drawString(100, H - 42, title or "Relatório de Ameaças STRIDE")
        canvas.setFont("Helvetica", 11)
        canvas.drawString(100, H - 58, subtitle or f"Análise automatizada por YOLO + {llm}" )
        canvas.setFillColor("black")
        canvas.setFont("Helvetica", 9)
        canvas.drawString(24, H - 86, f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas.restoreState()

    doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=24, rightMargin=24, topMargin=100, bottomMargin=36)
    story = []

    def _image_block(path, caption, max_h, legend=None):
        """Adiciona imagem com legenda textual opcional logo abaixo."""
        if not path or not os.path.exists(path):
            return
        try:
            img = RLImage(path)
            img._restrictSize(doc.width, max_h)
            img.hAlign = "LEFT"
            story.append(Paragraph(f"<b>{caption}</b>", ParagraphStyle("cap", parent=body, fontSize=11)))
            story.append(Spacer(1, 10))
            story.append(img)
            if legend:
                for text in legend:
                    story.append(Paragraph(f"{text}"))
        except Exception:
            pass

    max_img_h = 685
    _image_block(source_image_path, "Figura 1 — Diagrama original", max_img_h)
    story.append(PageBreak())
    _image_block(labeled_image_path, "Figura 2 — Diagrama anotado (detecções)", max_img_h, legend)
    story.append(PageBreak())

    # Limita o número de componentes (evita PDFs gigantes)
    iter_components = per_component if MAX_COMPONENTS <= 0 else per_component[:MAX_COMPONENTS]
    for comp_name, analysis, mitig in iter_components:
        story.append(Paragraph(comp_name, h_comp))

        # Análise STRIDE estruturada em listas por categoria
        story.append(Paragraph("Análise STRIDE:", h_label))
        a_sections = parse_stride_sections(analysis)
        has_any = any(a_sections.get(k) for k in _STRIDE_CANON)
        if has_any:
            for cat in _STRIDE_CANON:
                items = a_sections.get(cat) or []
                if not items:
                    continue
                story.append(Paragraph(cat, ParagraphStyle("cat", parent=body, fontName="Helvetica-Bold")))
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_sanitize_para(i), body), leftIndent=6) for i in items],
                        bulletType="bullet", start="•", leftIndent=12
                    )
                )
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph(_sanitize_para(analysis or "—"), body))
        story.append(Spacer(1, 6))

        # Mitigações estruturadas
        story.append(Paragraph("Mitigações sugeridas:", h_label))
        m_sections = parse_stride_sections(mitig)
        has_any_m = any(m_sections.get(k) for k in _STRIDE_CANON)
        if has_any_m:
            for cat in _STRIDE_CANON:
                items = m_sections.get(cat) or []
                if not items:
                    continue
                story.append(Paragraph(cat, ParagraphStyle("cat", parent=body, fontName="Helvetica-Bold")))
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_sanitize_para(i), body), leftIndent=6) for i in items],
                        bulletType="bullet", start="•", leftIndent=12
                    )
                )
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph(_sanitize_para(mitig or "—"), body))
        story.append(Spacer(1, 10))

    # Constrói documento com cabeçalho em todas as páginas
    doc.build(story, onFirstPage=_header, onLaterPages=_header)

# ============================================================
# Templates HTML (Jinja) embutidos em strings
# ============================================================

BASE_HTML = r"""
<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ page_title or 'Analisador STRIDE para Diagramas - Grupo 7 - 4IADT' }}</title>
  <style>
    :root{ --brand: {{ primary_color }}; --accent: {{ secondary_color }}; }
    html,body{ height:100%; }
    body{ font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; margin:0; background:#0B1220; color:#E5E7EB; }
    header{ background: #0D1326; border-bottom:1px solid #111827; color:#fff; padding: 18px 16px; position:sticky; top:0; z-index:10; }
    h1{ margin:0; font-size: 22px; }
    h2{ margin: 16px 0 8px; font-size: 18px; color:#E5E7EB; }
    main{ max-width: 980px; margin: 20px auto; padding: 0 16px; }
    .card{ background:#0F172A; border:1px solid #1F2937; border-radius:16px; padding:16px; box-shadow:0 10px 25px rgba(0,0,0,.35); margin-bottom:16px; }
    .grid{ display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:end; }
    .btn{ background: var(--brand); color:#0B1220; border:none; padding:10px 16px; border-radius:10px; cursor:pointer; text-decoration:none; font-weight:600; }
    .btn.secondary{ background: var(--accent); color:#0B1220; }
    .tip{ font-size: 12px; color:#9CA3AF; }
    .label{ font-weight:600; margin-bottom:6px; display:block; color:#CBD5E1; }
    input[type="text"], input[type="file"], input[type="color"]{
      width:100%; box-sizing:border-box; height:44px; border:1px solid #374151; border-radius:10px; padding:10px; background:#111827; color:#F9FAFB;
    }
    input[type="file"]{ padding:8px; }
    .preview-img{ max-width:100%; border-radius:12px; border:1px solid #1F2937; }
    footer{ text-align:center; padding:24px; color:#94A3B8; font-size:12px; }
    .brand-bar{ display:flex; align-items:center; gap:12px; }
    .brand-logo{ width:100px; height:36px; object-fit:contain; background:#0B1220; border-radius:8px; padding:4px; border:1px solid #1F2937; }
    .flash{ background:#1F2937; color:#F59E0B; padding:10px 12px; border:1px solid #374151; border-radius:8px; margin-bottom:12px; }
    .legend{ font-size: 14px; background:#0B1220; border:1px solid #1F2937; border-radius:10px; padding:10px; }
    .mono{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace; white-space:pre-wrap; }
    details{ background:#0B1220; border:1px solid #1F2937; border-radius:12px; margin:10px 0; }
    summary{ cursor:pointer; padding:10px 14px; user-select:none; font-weight:700; color:#E5E7EB; }
    details > .content{ padding: 0 14px 12px 14px; }
    ul{ margin:8px 0 12px 22px; }
    li{ margin:6px 0; }
    b{ color:#F3F4F6; }
    .model-selector { display: flex; gap: 10px; align-items: center; }
    .model-selector label { display: flex; align-items: center; gap: 8px; margin-right: 50px; }
    .model-selector img { width: 20px; height: 20px; }
  </style>
</head>
<body>
  <header>
    <div class="brand-bar">
      {% if brand_logo %}<img src="{{ brand_logo }}" class="brand-logo" alt="logo">{% endif %}
      <div>
        <h1>{{ header_title or 'Analisador STRIDE para Diagramas' }}</h1>
        <div class="tip">{{ header_subtitle or 'Detecta componentes (YOLO), gera análise e exporte PDF A4' }}</div>
      </div>
    </div>
  </header>
  <main>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        {% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </main>
  <footer>Analisador STRIDE para Diagramas - Grupo 7 - 4IADT • {{ year }}</footer>
</body>
</html>
"""

INDEX_HTML = r"""
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h2>Envie seu diagrama</h2>
  <form method="post" action="{{ url_for('analyze') }}" enctype="multipart/form-data">
    <div class="grid">
      <div>
        <label class="label">Diagrama (PNG/JPG até {{ max_mb }}MB)</label>
        <input type="file" name="diagram" accept="image/png,image/jpeg" required>
        <div class="tip">Dica: exporte do draw.io/diagrams.net/Figma com ~2000–3000px de largura.</div>
      </div>
      <div>
        <label class="label">Logo (opcional)</label>
        <input type="file" name="logo" accept="image/png,image/jpeg">
        <div class="tip">Usado no cabeçalho da página e no PDF.</div>
      </div>
    </div>

    <div class="grid" style="margin-top:12px;">
      <div>
        <label class="label">Título (branding)</label>
        <input type="text" name="title" placeholder="Relatório de Ameaças STRIDE">
      </div>
      <div>
        <label class="label">Subtítulo</label>
        <input type="text" id="subtitle" name="subtitle" placeholder="Análise automatizada por YOLO + Gemini">
      </div>
    </div>

    <div class="grid" style="margin-top:12px;">
      <div>
        <label class="label">Cor primária</label>
        <input type="color" name="primary" value="{{ primary_color }}">
      </div>
      <div>
        <label class="label">Cor secundária</label>
        <input type="color" name="secondary" value="{{ secondary_color }}">
      </div>
    </div>

    <div style="margin-top:12px;">
        <div class="model-selector">
            <label class="label">LLM Model
                <input type="radio" id="gemini" name="llm_model" value="Gemini" checked style="margin-left: 20px;">
                <label for="gemini"><img src="./static/gemini.png" alt="Gemini Icon">Gemini</label>
                <input type="radio" id="openai" name="llm_model" value="OpenAI">
                <label for="openai"><img src="./static/openai.ico" alt="OpenAI Icon">OpenAI</label>
            </label>
        </div>
    </div>

    <div style="margin-top:12px;">
      <label class="label"><input type="checkbox" name="quick" value="1" {% if quick_default %}checked{% endif %}> Modo rápido (pula LLM / usa placeholders)</label>
      <div class="tip">Excelente para testes rápidos; desmarque quando quiser texto completo do LLM.</div>
    </div>

    <div style="margin-top:16px; display:flex; gap:12px; align-items:center;">
      <button class="btn" type="submit">Analisar e gerar PDF</button>
      {% if disable_llm %}<div class="tip">LLM desabilitado — placeholders ativos. Defina GEMINI_API_KEY/OPENAI_API_KEY para ativar.</div>{% endif %}
    </div>
  </form>
</div>
<script>
    // Atualiza placeholder do subtítulo conforme o LLM selecionado
    document.addEventListener('DOMContentLoaded', function() {
        const textInput = document.getElementById('subtitle');
        const radioButtons = document.querySelectorAll('input[name="llm_model"]');
        function updatePlaceholder() {
            const selectedRadio = document.querySelector('input[name="llm_model"]:checked');
            const selectedModel = selectedRadio.value;
            const newPlaceholder = `Análise automatizada por YOLO + ${selectedModel}`;
            textInput.placeholder = newPlaceholder;
        }
        radioButtons.forEach(function(radio) {
            radio.addEventListener('change', updatePlaceholder);
        });
    });
</script>
{% endblock %}
"""

RESULTS_HTML = r"""
{% extends "base.html" %}
{% block content %}
<style>
  .toolbar { display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
  .btn { background: var(--brand); color:#0B1220; border:none; padding:10px 14px; border-radius:10px; cursor:pointer; text-decoration:none; font-weight:600; }
  .btn.secondary { background: var(--accent); color:#0B1220; }
  .component { background:#0F172A; border:1px solid #1F2937; border-radius:14px; padding:18px; margin-bottom:16px; box-shadow:0 6px 16px rgba(0,0,0,.35); }
  .component h3 { margin:0 0 6px; font-size:18px; color:var(--accent); }
</style>

<div class="card">
  <h2>Resultado</h2>
  <div class="grid">
    <div>
      <div class="label">Diagrama anotado</div>
      <img class="preview-img" src="{{ labeled_url }}" alt="labeled">
      {% if legend and legend|length %}
      <div class="legend" style="margin-top:8px;">
        <div class="label">Legenda</div>
        <ul>
          {% for line in legend %}<li class="mono">{{ line }}</li>{% endfor %}
        </ul>
      </div>
      {% endif %}
    </div>
    <div>
      <div class="label">Relatório</div>
      <p>Arquivo PDF A4 gerado com branding aplicado.</p>
      <a class="btn" href="{{ pdf_url }}" download>Baixar PDF</a>
      <a class="btn secondary" href="{{ url_for('index') }}">Nova análise</a>
      <div class="tip" style="margin-top:10px;">Salvo em: <span class="mono">{{ pdf_path }}</span></div>
    </div>
  </div>
</div>

<div class="card">
    <div class="toolbar">
        <button class="btn" id="expand-all">Expandir tudo</button>
        <button class="btn secondary" id="collapse-all">Recolher tudo</button>
    </div>

    <h2>Componentes detectados</h2>
    {% if components and components|length %}
        {% for c in components %}
        <article class="component" data-comp="{{ c.name }}">
            <h3>{{ loop.index }}. {{ c.name }}</h3>

            <details open>
                <summary>Análise STRIDE</summary>
                <div class="content">
                    {% set cats = ["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"] %}
                    {% set ns = namespace(has_struct=false) %}
                    {% for cat in cats %}
                    {% set items = c.analysis_sections_html.get(cat, []) if c.analysis_sections_html else [] %}
                    {% if items and items|length %}
                        {% set ns.has_struct = true %}
                        <details{% if loop.first %} open{% endif %}>
                        <summary>{{ cat }}</summary>
                        <div class="content">
                            <ul>
                            {% for it in items %}<li>{{ it|safe }}</li>{% endfor %}
                            </ul>
                        </div>
                        </details>
                    {% endif %}
                    {% endfor %}
                    {% if not ns.has_struct %}
                    <div class="mono">{{ c.analysis_html|safe }}</div>
                    {% endif %}
                </div>
            </details>

            <details>
            <summary>Mitigações</summary>
            <div class="content">
                {% set cats = ["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"] %}
                {% set ns2 = namespace(has_struct=false) %}
                {% for cat in cats %}
                {% set items = c.mitig_sections_html.get(cat, []) if c.mitig_sections_html else [] %}
                {% if items and items|length %}
                    {% set ns2.has_struct = true %}
                    <details>
                    <summary>{{ cat }}</summary>
                    <div class="content">
                        <ul>
                        {% for it in items %}<li>{{ it|safe }}</li>{% endfor %}
                        </ul>
                    </div>
                    </details>
                {% endif %}
                {% endfor %}
                {% if not ns2.has_struct %}
                <div class="mono">{{ c.mitigations_html|safe }}</div>
                {% endif %}
            </div>
            </details>
        </article>    
        {% endfor %}
    {% else %}
        <div>Nenhum componente detectado acima do limiar.</div>
    {% endif %}
</div>

<script>
  // Botões para expandir/recolher todos os <details>
  const allDetails = () => Array.from(document.querySelectorAll('details'));
  document.getElementById('expand-all').addEventListener('click', () => allDetails().forEach(d => d.open = true));
  document.getElementById('collapse-all').addEventListener('click', () => allDetails().forEach(d => d.open = false));
</script>
{% endblock %}
"""

# Registra os templates no Jinja a partir de strings
from jinja2 import DictLoader
app.jinja_loader = DictLoader({"base.html": BASE_HTML, "index.html": INDEX_HTML, "results.html": RESULTS_HTML})

# ============================================================
# Rotas Flask
# ============================================================

@app.get("/")
def index():
    """Tela inicial para upload do diagrama e seleção de opções."""
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "index.html")[0],
        page_title="Analisador STRIDE para Diagramas - Grupo 7 - 4IADT",
        primary_color="#7C3AED",   # roxo
        secondary_color="#22D3EE", # ciano
        header_title="Analisador STRIDE para Diagramas - Grupo 7 - 4IADT",
        header_subtitle="Detecta componentes (YOLO), gera análise e exporte PDF A4",
        brand_logo="./static/postech.png",
        max_mb=MAX_CONTENT_LENGTH_MB,
        disable_llm=DISABLE_LLM,
        quick_default=QUICK_DEFAULT,
        year=datetime.now().year,
    )

@app.post("/analyze")
def analyze():
    """
    Pipeline principal:
      1) valida upload e salva arquivos
      2) redimensiona imagem (se necessário)
      3) roda YOLO e aplica NMS
      4) anota imagem e gera legenda
      5) para cada componente único: consulta LLM (ou placeholders)
      6) monta PDF e exibe página de resultado
    """
    try:
        # ----------------- validações de upload -----------------
        if "diagram" not in request.files:
            flash("Selecione um diagrama.")
            return redirect(url_for("index"))
        diagram = request.files["diagram"]
        if diagram.filename == "":
            flash("Arquivo inválido.")
            return redirect(url_for("index"))
        if not allowed_file(diagram.filename):
            flash("Formato não permitido. Use PNG ou JPG.")
            return redirect(url_for("index"))

        # ----------------- parâmetros da UI -----------------
        llm = request.form.get("llm_model")
        title = request.form.get("title", "").strip() or "Relatório de Ameaças STRIDE"
        subtitle = request.form.get("subtitle", "").strip() or f"Análise automatizada por YOLO + {llm}"
        primary = request.form.get("primary", "#7C3AED")
        secondary = request.form.get("secondary", "#22D3EE")
        quick = request.form.get("quick", "1" if QUICK_DEFAULT else "0") == "1"

        # ----------------- salva diagrama -----------------
        filename = secure_filename(diagram.filename)
        src_path = os.path.join(UPLOAD_FOLDER, f"{int(time.time())}_{filename}")
        diagram.save(src_path)
        src_path = _resize_if_large(src_path, FAST_IMG_MAX_SIDE)

        # ----------------- opcional: logo -----------------
        logo_path = None
        if "logo" in request.files and request.files["logo"].filename:
            logo = request.files["logo"]
            if allowed_file(logo.filename):
                logo_filename = secure_filename(logo.filename)
                logo_path = os.path.join(UPLOAD_FOLDER, f"logo_{int(time.time())}_{logo_filename}")
                logo.save(logo_path)
        else:
            # fallback para um logo padrão em static/
            logo_filename = "postech.png"
            logo = Image.open(os.path.join(STATIC_FOLDER, logo_filename))
            logo_path = os.path.join(UPLOAD_FOLDER, f"logo_{int(time.time())}_{logo_filename}")
            logo.save(logo_path)

        # ----------------- YOLO: detecção -----------------
        model = get_yolo()
        results = model.predict(
            source=src_path,
            conf=max(0.25, YOLO_CONF),     # garante um mínimo para evitar ruído
            save=False,
            verbose=False,
            device=0 if _HAS_CUDA else "cpu",
            half=_HAS_CUDA,
            # imgsz=FAST_IMG_MAX_SIDE,    # pode habilitar se quiser fixar tamanho
            max_det=YOLO_MAX_DET,
            agnostic_nms=True,
        )
        names_map = getattr(model, "names", {})
        detections = nms_iou_filter(results[0].boxes.data, names_map, iou_threshold=NMS_IOU)

        # ----------------- anotação visual -----------------
        labeled_path, legend_lines = annotate_image(src_path, detections, color_hex=primary)

        # ----------------- gera análise por componente único -----------------
        components = []
        vistos = set()
        iter_boxes = detections if MAX_COMPONENTS <= 0 else detections[:MAX_COMPONENTS]
        for d in iter_boxes:
            class_name = d[6]
            comp = service_map.get(class_name, class_name)
            if comp in vistos:
                continue
            vistos.add(comp)

            # Se quick==True, força placeholders (como se LLM estivesse desabilitado)
            if quick:
                global DISABLE_LLM
                prev = DISABLE_LLM
                DISABLE_LLM = True
                analysis, mitig = call_gemini_stride("", comp)
                DISABLE_LLM = prev
            else:
                if llm == "Gemini":
                    analysis, mitig = call_gemini_stride(llm, comp)
                elif llm == "OpenAI":
                    analysis, mitig = call_openai_stride(llm, comp)
                else:
                    analysis, mitig = call_gemini_stride("", comp)

            # Estrutura para a UI: mantém bruto + versão por seções + HTML seguro
            a_secs = parse_stride_sections(analysis)
            m_secs = parse_stride_sections(mitig)
            a_secs_html = sections_to_html(a_secs)
            m_secs_html = sections_to_html(m_secs)

            components.append(
                {
                    "name": comp,
                    "analysis": analysis,
                    "mitigations": mitig,
                    "analysis_sections": a_secs,
                    "mitig_sections": m_secs,
                    "analysis_sections_html": a_secs_html,
                    "mitig_sections_html": m_secs_html,
                    "analysis_html": _sanitize_para(analysis),
                    "mitigations_html": _sanitize_para(mitig),
                }
            )

        # ----------------- gera PDF -----------------
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_name = f"relatorio_stride_{ts}.pdf"
        pdf_path = os.path.join(OUTPUT_FOLDER, pdf_name)
        build_pdf_a4(
            pdf_path=pdf_path,
            title=title,
            subtitle=subtitle,
            brand_color=primary,
            logo_path=logo_path,
            source_image_path=src_path,
            labeled_image_path=labeled_path,
            legend=legend_lines,
            llm=llm,
            per_component=[(c["name"], c["analysis"], c["mitigations"]) for c in components],
        )

        # ----------------- renderiza página de resultado -----------------
        return render_template_string(
            app.jinja_loader.get_source(app.jinja_env, "results.html")[0],
            page_title=title,
            primary_color=primary,
            secondary_color=secondary,
            header_title=title,
            header_subtitle=subtitle,
            brand_logo=(
                url_for("serve_file", folder="uploads", filename=os.path.basename(logo_path))
                if logo_path else None
            ),
            labeled_url=url_for("serve_file", folder="previews", filename=os.path.basename(labeled_path)),
            legend=legend_lines,
            components=components,
            pdf_url=url_for("serve_file", folder="outputs", filename=pdf_name),
            pdf_path=pdf_path,
            year=datetime.now().year,
        )
    except Exception as e:
        # Em caso de erro, loga stack trace e volta para a página inicial com mensagem
        traceback.print_exc()
        flash(f"Erro ao processar: {e}")
        return redirect(url_for("index"))

@app.get("/f/<path:folder>/<path:filename>")
def serve_file(folder: str, filename: str):
    """
    Rota para servir arquivos gerados:
      /f/uploads/<file>   → imagens enviadas (sem download forçado)
      /f/previews/<file>  → imagens anotadas (sem download forçado)
      /f/outputs/<file>   → PDFs (download)
    """
    if folder == "uploads":
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)
    if folder == "previews":
        return send_from_directory(PREVIEW_FOLDER, filename, as_attachment=False)
    if folder == "outputs":
        return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)
    return "Not found", 404

# ============================================================
# Dockerfile (template) – opcional
# ============================================================

DOCKERFILE_TEMPLATE = r"""
FROM python:3.11-slim
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y build-essential libjpeg62-turbo-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
COPY . /app
RUN pip install --no-cache-dir flask==3.0.3 google-generativeai==0.7.2 ultralytics==8.2.103 pillow==10.4.0 reportlab==4.2.2 python-dotenv==1.0.1 werkzeug==3.0.3
ENV GEMINI_API_KEY=""
ENV YOLO_WEIGHTS=/app/weights/treinamento_yolo_aws_best.pt
ENV APP_SECRET_KEY=change_me
EXPOSE 5000
CMD ["python", "app.py"]
"""

# ============================================================
# Entrypoint
# ============================================================

if __name__ == "__main__":
    import ssl

    # Certificado/Chave para HTTPS local (opcional)
    cert_path = os.getenv("SSL_CERT", "cert.pem")
    key_path  = os.getenv("SSL_KEY",  "key.pem")

    ssl_ctx = None
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # força TLS >= 1.2 quando disponível
        try:
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Sobe o Flask (com/sem SSL)
    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=ssl_ctx)
    # app.run(host="0.0.0.0", port=5000, debug=True)  # alternativa sem SSL
